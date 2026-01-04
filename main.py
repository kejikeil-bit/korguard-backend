"""
Korguard Beacon - FastAPI Backend
HIPAA Compliance Scanning API and Admin Dashboard
"""

from fastapi import FastAPI, HTTPException, Depends, Request, Form, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict
import re
import os
import hashlib
import secrets

# Initialize FastAPI app
app = FastAPI(
    title="Korguard Beacon API",
    description="HIPAA Compliance Scanning API for LLM Chat Interfaces",
    version="1.0.0"
)

# CORS Configuration - Allow extension requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to extension origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# DATA MODELS
# ============================================================================

class ScanRequest(BaseModel):
    text: str
    sensitivity: int = 3  # 1-4, default is 3 (Recommended)
    platform: Optional[str] = None

class ScanResult(BaseModel):
    status: str  # green, orange, red
    violations: List[Dict[str, Any]]
    scan_time: float
    scores: Optional[Dict[str, int]] = None
    reasons: Optional[List[Dict[str, Any]]] = None

class SubmitEventRequest(BaseModel):
    status: str
    platform: str
    timestamp: str
    text_length: int

class SettingsUpdate(BaseModel):
    sensitivity_level: Optional[int] = None
    text_red_behavior: Optional[str] = None  # 'block', 'warn_with_override', 'log_only'
    upload_red_behavior: Optional[str] = None  # 'block', 'warn_with_override', 'log_only'
    pdf_red_behavior: Optional[str] = None  # Backwards compatibility alias

class LoginRequest(BaseModel):
    username: str
    password: str

class FeedbackRequest(BaseModel):
    """User feedback for false positives/negatives"""
    text: str
    detected_status: str  # 'green', 'orange', 'red'
    expected_status: str  # What user thinks it should be
    feedback_type: str  # 'false_positive' or 'false_negative'
    platform: Optional[str] = None
    timestamp: Optional[str] = None
    detected_reasons: Optional[List[Dict[str, Any]]] = None

# ============================================================================
# IN-MEMORY DATA STORE (Replace with database in production)
# ============================================================================

class DataStore:
    def __init__(self):
        self.reset()
        
    def reset(self):
        self.sensitivity_level = 3
        # Text message RED behavior: 'block', 'warn_with_override', 'log_only'
        self.text_red_behavior = 'warn_with_override'
        # File upload RED behavior: 'block', 'warn_with_override', 'log_only'
        self.upload_red_behavior = 'warn_with_override'
        # Rules version - increment when rules change to trigger client refresh
        self.rules_version = 1
        self.stats = {
            'total_scans': 0,
            'green_count': 0,
            'orange_count': 0,
            'red_count': 0,
            'violations_by_title': defaultdict(int),
            'violations_by_platform': defaultdict(lambda: {'green': 0, 'orange': 0, 'red': 0}),
            'violations_by_type': defaultdict(int),
            'overrides': {'orange': 0, 'red': 0},
            'submit_times': [],  # List of (status, time_seconds)
            # File upload stats (PDFs, docs, images, etc.)
            'file_scans': 0,
            'file_green': 0,
            'file_orange': 0,
            'file_red': 0,
            'file_blocked': 0,
            'file_overrides': 0,
            'file_by_type': defaultdict(lambda: {'scans': 0, 'green': 0, 'orange': 0, 'red': 0}),
            # De-identification coaching stats
            'coaching_shown': 0,
            'coaching_used_safer': 0,
            'coaching_kept_original': 0,
            'coaching_undid': 0,
            'coaching_by_status': {'orange': 0, 'red': 0},
            'coaching_safer_used_by_status': {'orange': 0, 'red': 0},
            # Feedback for automated training
            'feedback': {
                'false_positives': [],  # List of {text, detected_status, expected_status, timestamp}
                'false_negatives': [],  # List of {text, detected_status, expected_status, timestamp}
                'total_feedback': 0
            }
        }
        self.sessions = {}  # session_token -> {username, expires}
        
    def get_stats_summary(self) -> Dict:
        total = self.stats['total_scans'] or 1  # Avoid division by zero
        file_total = self.stats['file_scans'] or 1
        return {
            'total_scans': self.stats['total_scans'],
            'percentages': {
                'green': round(self.stats['green_count'] / total * 100, 1),
                'orange': round(self.stats['orange_count'] / total * 100, 1),
                'red': round(self.stats['red_count'] / total * 100, 1),
            },
            'counts': {
                'green': self.stats['green_count'],
                'orange': self.stats['orange_count'],
                'red': self.stats['red_count'],
            },
            'by_title': dict(self.stats['violations_by_title']),
            'by_platform': {k: dict(v) for k, v in self.stats['violations_by_platform'].items()},
            'by_type': dict(self.stats['violations_by_type']),
            'overrides': self.stats['overrides'],
            'sensitivity_level': self.sensitivity_level,
            'text_red_behavior': self.text_red_behavior,
            'upload_red_behavior': self.upload_red_behavior,
            # Backwards compatibility
            'pdf_red_behavior': self.upload_red_behavior,
            # File upload stats (all file types)
            'file_stats': {
                'total': self.stats['file_scans'],
                'green': self.stats['file_green'],
                'orange': self.stats['file_orange'],
                'red': self.stats['file_red'],
                'blocked': self.stats['file_blocked'],
                'overrides': self.stats['file_overrides'],
                'by_type': {k: dict(v) for k, v in self.stats['file_by_type'].items()},
                'percentages': {
                    'green': round(self.stats['file_green'] / file_total * 100, 1),
                    'orange': round(self.stats['file_orange'] / file_total * 100, 1),
                    'red': round(self.stats['file_red'] / file_total * 100, 1),
                }
            },
            # Backwards compatibility alias
            'pdf_stats': {
                'total': self.stats['file_scans'],
                'green': self.stats['file_green'],
                'orange': self.stats['file_orange'],
                'red': self.stats['file_red'],
                'blocked': self.stats['file_blocked'],
                'overrides': self.stats['file_overrides'],
            },
            # De-identification coaching stats
            'coaching_stats': {
                'shown': self.stats['coaching_shown'],
                'used_safer': self.stats['coaching_used_safer'],
                'kept_original': self.stats['coaching_kept_original'],
                'undid': self.stats['coaching_undid'],
                'by_status': dict(self.stats['coaching_by_status']),
                'safer_used_by_status': dict(self.stats['coaching_safer_used_by_status']),
                'safer_adoption_rate': round(
                    self.stats['coaching_used_safer'] / max(self.stats['coaching_shown'], 1) * 100, 1
                )
            }
        }

store = DataStore()

# ============================================================================
# RULES STORE - Backend-updatable HIPAA rules
# ============================================================================

class RulesStore:
    """
    Stores HIPAA detection rules that can be updated from the backend.
    Extensions fetch these rules periodically and cache them locally.
    """
    
    def __init__(self):
        self.version = 2  # Increment when rules change (v2: fixed lowercase name/DOB detection)
        self.last_updated = datetime.utcnow().isoformat()
        
        # Default rules (same as hardcoded in HIPAARulesEngine)
        self.strong_identifiers = {
            'full_name': {
                'patterns': [
                    r'\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b',
                    r'\b[A-Z][a-z]{2,15}\s+[A-Z][a-z]{2,15}\b',
                    # More flexible: "patient name is john smith" - handles lowercase names
                    r'(?:patient|client|member)(?:\'s)?\s+(?:name\s+is|named?|is|:)\s*[A-Za-z]{2,}\s+[A-Za-z]{2,}',
                    # Natural language: "name is john smith", "named john smith"
                    r'\b(?:name\s+is|named)\s+[A-Za-z]{2,}\s+[A-Za-z]{2,}',
                ],
                'description': 'Full name (first + last)',
                'score': 2
            },
            'ssn': {
                'patterns': [
                    r'\b\d{3}-\d{2}-\d{4}\b',
                    r'\b(?:SSN|Social\s*Security(?:\s*Number)?)[:\s#]*\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
                ],
                'description': 'Social Security Number',
                'score': 3
            },
            'mrn': {
                'patterns': [
                    r'\b(?:MRN|Medical\s*Record(?:\s*Number)?|Chart\s*(?:Number|#|ID))[:\s#]+[A-Z0-9\-]+\b',
                    r'\bMRN\s*[:\s#]?\s*[A-Z0-9]{4,}\b',
                ],
                'description': 'Medical Record Number',
                'score': 2
            },
            'full_address': {
                'patterns': [
                    r'\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Way|Place|Pl\.?|Circle|Cir\.?)\b(?:[,\s]+(?:Apt\.?|Suite|Ste\.?|Unit|#)\s*\d+)?',
                ],
                'description': 'Street address',
                'score': 2
            },
            'full_dob': {
                'patterns': [
                    # DOB with "is": "date of birth is October 27 2004" or "date of birth is october 27 2004"
                    r'\b(?:DOB|date\s*of\s*birth|born(?:\s*on)?)\s*(?:is|:)?\s*(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|[A-Za-z]+\s+\d{1,2},?\s+\d{4})\b',
                    # Standalone dates with month names (case-insensitive, with or without comma)
                    r'\b(?:january|february|march|april|may|june|july|august|september|october|november|december)\s+\d{1,2},?\s+\d{4}\b',
                    # Birth date natural language: "birthday is", "born on"
                    r'\b(?:birth\s*(?:date|day)\s*(?:is|:)?|born\s+(?:on\s+)?)\s*(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|[A-Za-z]+\s+\d{1,2},?\s+\d{4})',
                ],
                'description': 'Date of birth or full date',
                'score': 2
            },
            'email': {
                'patterns': [
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                ],
                'description': 'Email address',
                'score': 2
            },
            'phone': {
                'patterns': [
                    r'\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
                ],
                'description': 'Phone number',
                'score': 2
            },
        }
        
        self.weak_identifiers = {
            'first_name_only': {
                'patterns': [
                    r'\b(?:patient|client)\s+(?:named?|is|:)\s*([A-Z][a-z]{2,})\b',
                    r'\b(?:Mr\.|Mrs\.|Ms\.)\s+([A-Z][a-z]+)\b',
                ],
                'description': 'First name only',
                'score': 1
            },
            'city_only': {
                'patterns': [
                    r'\b(?:in|from|at|lives?\s*in)\s+([A-Za-z]+(?:\s+[A-Za-z]+)?),?\s+(?:[A-Z]{2}|[A-Za-z]+)\b',
                    r'\b(?:resident\s+of|resides?\s+in)\s+([A-Za-z]+(?:\s+[A-Za-z]+)?)',
                ],
                'description': 'City/location only',
                'score': 1
            },
            'age_specific': {
                'patterns': [
                    r'\b(?:age[d]?\s*[:=]?\s*)?(9[0-9]|1[0-4]\d)\s*(?:years?|y\.?o\.?|year[s]?\s*old)\b',
                ],
                'description': 'Age over 89',
                'score': 1
            },
            'zip_code': {
                'patterns': [
                    r'\b\d{5}(?:-\d{4})?\b',
                ],
                'description': 'ZIP code',
                'score': 1
            },
        }
        
        self.health_context = {
            'explicit_diagnosis': {
                'patterns': [
                    r'\b(?:diagnosed\s+with|diagnosis(?:\s+of)?[:\s]+|has\s+(?:been\s+)?diagnosed)\s+\w+',
                    r'\b(?:cancer|diabetes|HIV|AIDS|hepatitis|tuberculosis|TB|COPD|CHF|CAD|CKD|ESRD|cirrhosis|lupus|MS|multiple\s+sclerosis|parkinson|alzheimer|dementia|schizophrenia|bipolar|major\s+depression|anxiety\s+disorder|PTSD|autism|epilepsy|seizure\s+disorder)\b',
                    r'\b(?:stage\s+(?:I{1,4}|[1-4])|terminal|metastatic|malignant|benign)\s+\w+',
                ],
                'description': 'Explicit diagnosis',
                'score': 2
            },
            'treatment_procedure': {
                'patterns': [
                    r'\b(?:surgery|chemotherapy|chemo|radiation|dialysis|transplant|amputation|intubat|ventilat|transfusion|infusion|biopsy)\b',
                    r'\b(?:admitted|discharged|hospitalized|inpatient|outpatient|ER\s+visit|emergency\s+room)\b',
                ],
                'description': 'Treatment or procedure',
                'score': 2
            },
            'medications': {
                'patterns': [
                    r'\b(?:taking|prescribed|on|started|discontinued)\s+(?:medication|meds?|drug)s?\b',
                    r'\b(?:warfarin|metformin|insulin|lisinopril|atorvastatin|metoprolol|omeprazole|amlodipine|gabapentin|hydrocodone|oxycodone|morphine|fentanyl)\b',
                ],
                'description': 'Medication reference',
                'score': 2
            },
            'patient_context': {
                'patterns': [
                    r'\b(?:my\s+patient|the\s+patient|this\s+patient|patient\'s|patient\s+with)\b',
                    # "Patient name is", "Patient is", "Patient has", etc. - clear patient context
                    r'\bpatient\s+(?:name|is|has|was|will|presents|presenting|complaining|diagnosed|admitted|discharged|taking|prescribed)\b',
                    r'\b(?:chart|medical\s+record|clinical\s+note|progress\s+note|H&P|history\s+and\s+physical|discharge\s+summary)\b',
                    r'\b(?:chief\s+complaint|presenting\s+with|presents\s+with|complaining\s+of)\b',
                ],
                'description': 'Patient/clinical context',
                'score': 1
            },
            'general_health': {
                'patterns': [
                    r'\b(?:symptoms?|condition|illness|disease|disorder|syndrome|treatment|therapy|prognosis)\b',
                    r'\b(?:hospital|clinic|physician|doctor|nurse|provider|specialist)\b',
                ],
                'description': 'General health terms',
                'score': 1
            },
        }
        
        # Scoring thresholds
        self.thresholds = {
            'red': {'identifier_score': 2, 'health_score': 2},
            'orange': {'identifier_score': 1, 'health_score': 1},
        }
        
        # Custom keywords (user-defined)
        self.custom_keywords = []
    
    def get_rules(self) -> Dict:
        """Return all rules in a format suitable for the frontend"""
        return {
            'version': self.version,
            'last_updated': self.last_updated,
            'strong_identifiers': self.strong_identifiers,
            'weak_identifiers': self.weak_identifiers,
            'health_context': self.health_context,
            'thresholds': self.thresholds,
            'custom_keywords': self.custom_keywords,
            'settings': {
                'sensitivity_level': store.sensitivity_level,
                'text_red_behavior': store.text_red_behavior,
                'upload_red_behavior': store.upload_red_behavior,
            }
        }
    
    def update_rules(self, updates: Dict) -> None:
        """Update rules and increment version"""
        if 'strong_identifiers' in updates:
            self.strong_identifiers.update(updates['strong_identifiers'])
        if 'weak_identifiers' in updates:
            self.weak_identifiers.update(updates['weak_identifiers'])
        if 'health_context' in updates:
            self.health_context.update(updates['health_context'])
        if 'thresholds' in updates:
            self.thresholds.update(updates['thresholds'])
        if 'custom_keywords' in updates:
            self.custom_keywords = updates['custom_keywords']
        
        self.version += 1
        self.last_updated = datetime.utcnow().isoformat()
    
    def add_pattern(self, category: str, identifier: str, pattern: str) -> bool:
        """Add a new pattern to an identifier"""
        target = None
        if category == 'strong':
            target = self.strong_identifiers
        elif category == 'weak':
            target = self.weak_identifiers
        elif category == 'health':
            target = self.health_context
        
        if target and identifier in target:
            if pattern not in target[identifier]['patterns']:
                target[identifier]['patterns'].append(pattern)
                self.version += 1
                self.last_updated = datetime.utcnow().isoformat()
                return True
        return False
    
    def remove_pattern(self, category: str, identifier: str, pattern_index: int) -> bool:
        """Remove a pattern from an identifier by index"""
        target = None
        if category == 'strong':
            target = self.strong_identifiers
        elif category == 'weak':
            target = self.weak_identifiers
        elif category == 'health':
            target = self.health_context
        
        if target and identifier in target:
            patterns = target[identifier]['patterns']
            if 0 <= pattern_index < len(patterns):
                patterns.pop(pattern_index)
                self.version += 1
                self.last_updated = datetime.utcnow().isoformat()
                return True
        return False


rules_store = RulesStore()

# Admin credentials (in production, use proper auth with hashed passwords)
ADMIN_CREDENTIALS = {
    'admin': hashlib.sha256('beacon2024'.encode()).hexdigest()
}

# ============================================================================
# HIPAA PRIVACY RULE ENGINE v2
# Precisely HIPAA-driven detection focused on PHI disclosure
# Reference: HHS Privacy Rule Summary - 45 CFR § 164.514
# ============================================================================

class HIPAARulesEngine:
    """
    HIPAA Privacy Rule compliance detection engine v2.
    
    Key principles:
    - PHI = Health/treatment/payment info + Identifier that can identify an individual
    - First-person pronouns (I/me/my/we/us) NEVER trigger warnings alone
    - RED is reserved for HIGH-CONFIDENCE PHI disclosure
    - De-identified or generalized information is GREEN
    """
    
    # ========================================================================
    # STAGE A: FEATURE DEFINITIONS
    # ========================================================================
    
    # Strong identifiers (HIPAA Safe Harbor list) - Score 2
    STRONG_IDENTIFIERS = {
        'full_name': {
            'patterns': [
                # Full names with titles
                r'\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b',
                # Two capitalized words that look like first + last name
                r'\b[A-Z][a-z]{2,15}\s+[A-Z][a-z]{2,15}\b',
                # More flexible: "patient name is john smith", "patient named john smith", etc.
                # This pattern handles lowercase names in patient context
                r'(?:patient|client|member)(?:\'s)?\s+(?:name\s+is|named?|is|:)\s*[A-Za-z]{2,}\s+[A-Za-z]{2,}',
                # Natural language: "name is john smith", "named john smith"
                r'\b(?:name\s+is|named)\s+[A-Za-z]{2,}\s+[A-Za-z]{2,}',
            ],
            'description': 'Full name (first + last)',
            'score': 2
        },
        'ssn': {
            'patterns': [
                r'\b\d{3}-\d{2}-\d{4}\b',
                r'\b(?:SSN|Social\s*Security(?:\s*Number)?)[:\s#]*\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
            ],
            'description': 'Social Security Number',
            'score': 3  # Highest - always RED with health context
        },
        'mrn': {
            'patterns': [
                r'\b(?:MRN|Medical\s*Record(?:\s*Number)?|Chart\s*(?:Number|#|ID))[:\s#]+[A-Z0-9\-]+\b',
                r'\bMRN\s*[:\s#]?\s*[A-Z0-9]{4,}\b',
            ],
            'description': 'Medical Record Number',
            'score': 2
        },
        'full_address': {
            'patterns': [
                # Street address with number
                r'\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Way|Place|Pl\.?|Circle|Cir\.?)\b(?:[,\s]+(?:Apt\.?|Suite|Ste\.?|Unit|#)\s*\d+)?',
            ],
            'description': 'Street address',
            'score': 2
        },
        'full_dob': {
            'patterns': [
                # DOB with "is": "date of birth is October 27 2004" or "date of birth is october 27 2004"
                r'\b(?:DOB|date\s*of\s*birth|born(?:\s*on)?)\s*(?:is|:)?\s*(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|[A-Za-z]+\s+\d{1,2},?\s+\d{4})\b',
                # Standalone dates with month names (case-insensitive, with or without comma)
                r'\b(?:january|february|march|april|may|june|july|august|september|october|november|december)\s+\d{1,2},?\s+\d{4}\b',
                # Birth date natural language: "birthday is", "born on"
                r'\b(?:birth\s*(?:date|day)\s*(?:is|:)?|born\s+(?:on\s+)?)\s*(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|[A-Za-z]+\s+\d{1,2},?\s+\d{4})',
            ],
            'description': 'Date of birth or full date',
            'score': 2
        },
        'email': {
            'patterns': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            ],
            'description': 'Email address',
            'score': 2
        },
        'phone': {
            'patterns': [
                r'\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
            ],
            'description': 'Phone number',
            'score': 2
        },
    }
    
    # Weak/partial identifiers - Score 1
    WEAK_IDENTIFIERS = {
        'first_name_only': {
            'patterns': [
                # Single capitalized word in patient context (but not common words)
                r'\b(?:patient|client)\s+(?:named?|is|:)\s*([A-Z][a-z]{2,})\b',
                # Mr/Mrs with single name
                r'\b(?:Mr\.|Mrs\.|Ms\.)\s+([A-Z][a-z]+)\b',
            ],
            'description': 'First name only',
            'score': 1
        },
        'city_only': {
            'patterns': [
                # "lives in Wylie TX", "from Chicago, IL", "in New York NY"
                r'\b(?:in|from|at|lives?\s*in)\s+([A-Za-z]+(?:\s+[A-Za-z]+)?),?\s+(?:[A-Z]{2}|[A-Za-z]+)\b',
                # "resident of Chicago", "resides in Dallas"
                r'\b(?:resident\s+of|resides?\s+in)\s+([A-Za-z]+(?:\s+[A-Za-z]+)?)',
            ],
            'description': 'City/location only',
            'score': 1
        },
        'age_specific': {
            'patterns': [
                # Age over 89 (HIPAA identifier)
                r'\b(?:age[d]?\s*[:=]?\s*)?(9[0-9]|1[0-4]\d)\s*(?:years?|y\.?o\.?|year[s]?\s*old)\b',
            ],
            'description': 'Age over 89',
            'score': 1
        },
        'zip_code': {
            'patterns': [
                r'\b\d{5}(?:-\d{4})?\b',
            ],
            'description': 'ZIP code',
            'score': 1
        },
        'initial_or_abbrev': {
            'patterns': [
                # Mr. K, Mrs. J, etc.
                r'\b(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s+[A-Z]\.?\b',
            ],
            'description': 'Name initial only',
            'score': 1
        },
    }
    
    # Health context keywords - determines health_score
    HEALTH_CONTEXT = {
        'explicit_diagnosis': {
            'patterns': [
                # Specific diagnoses
                r'\b(?:diagnosed\s+with|diagnosis(?:\s+of)?[:\s]+|has\s+(?:been\s+)?diagnosed)\s+\w+',
                r'\b(?:cancer|diabetes|HIV|AIDS|hepatitis|tuberculosis|TB|COPD|CHF|CAD|CKD|ESRD|cirrhosis|lupus|MS|multiple\s+sclerosis|parkinson|alzheimer|dementia|schizophrenia|bipolar|major\s+depression|anxiety\s+disorder|PTSD|autism|epilepsy|seizure\s+disorder)\b',
                r'\b(?:stage\s+(?:I{1,4}|[1-4])|terminal|metastatic|malignant|benign)\s+\w+',
            ],
            'description': 'Explicit diagnosis',
            'score': 2
        },
        'treatment_procedure': {
            'patterns': [
                r'\b(?:surgery|chemotherapy|chemo|radiation|dialysis|transplant|amputation|intubat|ventilat|transfusion|infusion|biopsy)\b',
                r'\b(?:admitted|discharged|hospitalized|inpatient|outpatient|ER\s+visit|emergency\s+room)\b',
            ],
            'description': 'Treatment or procedure',
            'score': 2
        },
        'medications': {
            'patterns': [
                r'\b(?:taking|prescribed|on|started|discontinued)\s+(?:medication|meds?|drug)s?\b',
                r'\b(?:warfarin|metformin|insulin|lisinopril|atorvastatin|metoprolol|omeprazole|amlodipine|gabapentin|hydrocodone|oxycodone|morphine|fentanyl)\b',
            ],
            'description': 'Medication reference',
            'score': 2
        },
        'lab_imaging': {
            'patterns': [
                r'\b(?:CBC|BMP|CMP|A1C|HbA1c|PSA|TSH|lipid\s+panel|liver\s+function|kidney\s+function)\b',
                r'\b(?:CT\s+scan|MRI|X-ray|ultrasound|mammogram|colonoscopy|endoscopy|EKG|ECG|echocardiogram)\b',
            ],
            'description': 'Lab or imaging results',
            'score': 2
        },
        'patient_context': {
            'patterns': [
                r'\b(?:my\s+patient|the\s+patient|this\s+patient|patient\'s|patient\s+with)\b',
                # "Patient name is", "Patient is", "Patient has", etc. - clear patient context
                r'\bpatient\s+(?:name|is|has|was|will|presents|presenting|complaining|diagnosed|admitted|discharged|taking|prescribed)\b',
                r'\b(?:chart|medical\s+record|clinical\s+note|progress\s+note|H&P|history\s+and\s+physical|discharge\s+summary)\b',
                r'\b(?:chief\s+complaint|presenting\s+with|presents\s+with|complaining\s+of)\b',
            ],
            'description': 'Patient/clinical context',
            'score': 1
        },
        'general_health': {
            'patterns': [
                r'\b(?:symptoms?|condition|illness|disease|disorder|syndrome|treatment|therapy|prognosis)\b',
                r'\b(?:hospital|clinic|physician|doctor|nurse|provider|specialist)\b',
            ],
            'description': 'General health terms',
            'score': 1
        },
    }
    
    # First-person exemption patterns - these NEVER trigger warnings alone
    FIRST_PERSON_PATTERNS = [
        r'\b(?:I|I\'m|I\'ve|I\'ll|I\'d|me|my|myself|mine|we|we\'re|we\'ve|we\'ll|us|our|ours|ourselves)\b',
    ]
    
    # De-identification patterns (safe generalizations)
    DEIDENTIFIED_PATTERNS = [
        r'\b(?:a|an|the)\s+(?:\d{1,2}[-\s]?year[-\s]?old|elderly|middle[-\s]?aged|young|teenage|adolescent|pediatric|geriatric)\s+(?:male|female|man|woman|patient|person|individual)\b',
        r'\b(?:patients?\s+with|people\s+with|individuals?\s+with|those\s+with|someone\s+with)\s+\w+\b',
        r'\b(?:in\s+(?:his|her|their)\s+(?:\d0s|forties|fifties|sixties|seventies|eighties))\b',
    ]
    
    def __init__(self, sensitivity: int = 3):
        """
        Initialize the rules engine with a sensitivity level (1-4).
        1 = Low (very strict, RED only for obvious PHI)
        2 = Medium (balanced)
        3 = Recommended (default)
        4 = High (more cautious)
        """
        self.sensitivity = min(max(sensitivity, 1), 4)
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for performance."""
        # Compile strong identifiers
        self.compiled_strong = {}
        for name, config in self.STRONG_IDENTIFIERS.items():
            self.compiled_strong[name] = {
                **config,
                'compiled': [re.compile(p, re.IGNORECASE) for p in config['patterns']]
            }
        
        # Compile weak identifiers
        self.compiled_weak = {}
        for name, config in self.WEAK_IDENTIFIERS.items():
            self.compiled_weak[name] = {
                **config,
                'compiled': [re.compile(p, re.IGNORECASE) for p in config['patterns']]
            }
        
        # Compile health context
        self.compiled_health = {}
        for name, config in self.HEALTH_CONTEXT.items():
            self.compiled_health[name] = {
                **config,
                'compiled': [re.compile(p, re.IGNORECASE) for p in config['patterns']]
            }
        
        # Compile first-person patterns
        self.compiled_first_person = [
            re.compile(p, re.IGNORECASE) for p in self.FIRST_PERSON_PATTERNS
        ]
        
        # Compile de-identification patterns
        self.compiled_deidentified = [
            re.compile(p, re.IGNORECASE) for p in self.DEIDENTIFIED_PATTERNS
        ]
    
    def scan(self, text: str) -> Dict:
        """
        Scan text for HIPAA Privacy Rule PHI disclosure.
        
        Returns:
            {
                "status": "green" | "orange" | "red",
                "reasons": [...],
                "scores": {"health_score": int, "identifier_score": int},
                "scan_time": float
            }
        """
        import time
        start_time = time.time()
        
        # Stage A: Feature extraction
        reasons = []
        health_reasons = []
        identifier_reasons = []
        
        # Check if text is primarily first-person (about the author, not a patient)
        is_first_person = self._is_first_person_context(text)
        
        # Check if text uses de-identified/generalized language
        is_deidentified = self._is_deidentified(text)
        
        # Extract health context features
        health_score = 0
        for name, config in self.compiled_health.items():
            for pattern in config['compiled']:
                matches = pattern.findall(text)
                if matches:
                    unique_matches = list(set(m if isinstance(m, str) else m[0] for m in matches[:3]))
                    if unique_matches:
                        health_reasons.append({
                            'type': 'health',
                            'subtype': name,
                            'description': config['description'],
                            'snippets': unique_matches,
                            'score': config['score']
                        })
                        health_score = max(health_score, config['score'])
        
        # Extract identifier features
        identifier_score = 0
        strong_id_count = 0
        weak_id_count = 0
        
        # Check strong identifiers
        for name, config in self.compiled_strong.items():
            for pattern in config['compiled']:
                matches = pattern.findall(text)
                if matches:
                    unique_matches = list(set(m if isinstance(m, str) else m[0] for m in matches[:3]))
                    # Filter out common false positives
                    unique_matches = self._filter_false_positives(unique_matches, name)
                    if unique_matches:
                        identifier_reasons.append({
                            'type': 'identifier',
                            'subtype': name,
                            'description': config['description'],
                            'snippets': unique_matches,
                            'score': config['score']
                        })
                        identifier_score = max(identifier_score, config['score'])
                        strong_id_count += 1
        
        # Check weak identifiers
        for name, config in self.compiled_weak.items():
            for pattern in config['compiled']:
                matches = pattern.findall(text)
                if matches:
                    unique_matches = list(set(m if isinstance(m, str) else m[0] for m in matches[:3]))
                    unique_matches = self._filter_false_positives(unique_matches, name)
                    if unique_matches:
                        identifier_reasons.append({
                            'type': 'identifier',
                            'subtype': name,
                            'description': config['description'],
                            'snippets': unique_matches,
                            'score': config['score']
                        })
                        if identifier_score < 2:  # Don't downgrade from strong
                            identifier_score = max(identifier_score, config['score'])
                        weak_id_count += 1
        
        # Multiple weak identifiers = stronger identification
        if weak_id_count >= 3:
            identifier_score = max(identifier_score, 2)
        
        # Combine reasons
        reasons = health_reasons + identifier_reasons
        
        # Stage B: Classification
        status = self._determine_status(
            health_score=health_score,
            identifier_score=identifier_score,
            is_first_person=is_first_person,
            is_deidentified=is_deidentified,
            reasons=reasons
        )
        
        scan_time = time.time() - start_time
        
        return {
            'status': status,
            'reasons': reasons,
            'violations': self._format_violations(reasons, status),  # Backwards compatibility
            'scores': {
                'health_score': health_score,
                'identifier_score': identifier_score
            },
            'is_first_person': is_first_person,
            'is_deidentified': is_deidentified,
            'scan_time': round(scan_time * 1000, 2)
        }
    
    def _is_first_person_context(self, text: str) -> bool:
        """
        Check if the text is primarily about the author themselves.
        Returns True if text uses first-person pronouns without patient context.
        """
        # Count first-person pronouns
        first_person_count = sum(
            len(p.findall(text)) for p in self.compiled_first_person
        )
        
        # Check for explicit patient context (third-party)
        patient_context = bool(re.search(
            r'\b(?:my\s+patient|the\s+patient|patient\s+(?:named?|is|has)|his\s+(?:chart|record|diagnosis)|her\s+(?:chart|record|diagnosis)|their\s+(?:chart|record|diagnosis))\b',
            text, re.IGNORECASE
        ))
        
        # If lots of first-person and no patient context, it's about the author
        if first_person_count >= 2 and not patient_context:
            return True
        
        return False
    
    def _is_deidentified(self, text: str) -> bool:
        """Check if text uses de-identified/generalized language."""
        for pattern in self.compiled_deidentified:
            if pattern.search(text):
                return True
        return False
    
    def _filter_false_positives(self, matches: List[str], identifier_type: str) -> List[str]:
        """Filter out common false positives from matches."""
        filtered = []
        
        # Expanded false positive lists
        false_positive_names = {
            # Common words
            'the', 'this', 'that', 'here', 'there', 'what', 'when', 'where', 'which', 'who', 'why', 'how',
            'help', 'please', 'thank', 'thanks', 'hello', 'dear', 'best', 'regards', 'sincerely',
            # Days
            'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
            # Months
            'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august',
            'september', 'october', 'november', 'december',
            # Common phrases/words that trigger false positives
            'simple', 'terms', 'explain', 'describe', 'tell', 'show', 'give', 'provide', 'create', 'make',
            'write', 'draft', 'generate', 'summarize', 'outline', 'list', 'detail', 'clarify',
            # Common adjectives/adverbs
            'better', 'best', 'good', 'great', 'nice', 'fine', 'well', 'very', 'really', 'quite',
            'more', 'most', 'less', 'least', 'some', 'many', 'much', 'few', 'little',
            # Common verbs
            'can', 'could', 'should', 'would', 'will', 'shall', 'may', 'might', 'must',
            'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had',
            'do', 'does', 'did', 'done', 'get', 'got', 'give', 'gave', 'take', 'took',
            # Common nouns
            'way', 'thing', 'part', 'time', 'day', 'year', 'month', 'week', 'hour', 'minute',
            'person', 'people', 'man', 'woman', 'child', 'children', 'group', 'team',
            # Common prepositions/conjunctions
            'and', 'or', 'but', 'if', 'then', 'else', 'for', 'with', 'from', 'into', 'onto',
            'about', 'above', 'across', 'after', 'against', 'along', 'among', 'around', 'at',
            'before', 'behind', 'below', 'beneath', 'beside', 'between', 'beyond', 'by',
            'during', 'except', 'inside', 'near', 'off', 'on', 'over', 'through', 'to', 'under', 'until',
            # Locations
            'new', 'york', 'los', 'angeles', 'san', 'francisco', 'chicago', 'houston'
        }
        
        false_positive_locations = {
            'local', 'area', 'region', 'place', 'location', 'spot', 'site', 'venue', 'space',
            'simple', 'terms', 'way', 'thing', 'part', 'time', 'day', 'year', 'month',
            'here', 'there', 'where', 'everywhere', 'somewhere', 'anywhere', 'nowhere'
        }
        
        for match in matches:
            match_lower = match.lower().strip() if isinstance(match, str) else str(match).lower()
            
            # Skip very short matches
            if len(match_lower) < 2:
                continue
            
            # Filter by identifier type
            if identifier_type in ('full_name', 'first_name_only'):
                words = match_lower.split()
                
                # Check if any word is a known false positive
                if any(w in false_positive_names for w in words):
                    continue
                
                # Names should be at least 2 characters per word
                if any(len(w) < 2 for w in words):
                    continue
                
                # Names shouldn't be common phrases
                common_phrases = ['simple terms', 'in simple', 'explain in', 'tell me', 'help me']
                if any(phrase in match_lower for phrase in common_phrases):
                    continue
                
                # If it's a single word and it's a common word, reject
                if len(words) == 1 and words[0] in false_positive_names:
                    continue
            
            if identifier_type == 'city_only':
                words = match_lower.split()
                
                # Check if any word is a known false positive location
                if any(w in false_positive_locations for w in words):
                    continue
                
                # Single word locations that are common words should be rejected
                if len(words) == 1 and words[0] in false_positive_locations:
                    continue
                
                # Common phrases that trigger false positives
                common_location_phrases = ['in simple', 'simple terms', 'local area', 'in terms']
                if any(phrase in match_lower for phrase in common_location_phrases):
                    continue
            
            filtered.append(match)
        
        return filtered
    
    def _determine_status(
        self,
        health_score: int,
        identifier_score: int,
        is_first_person: bool,
        is_deidentified: bool,
        reasons: List[Dict]
    ) -> str:
        """
        Determine status based on scores and context.
        
        Decision rules:
        - First-person context without patient references → GREEN
        - De-identified/generalized language → GREEN
        - No health context → GREEN (even with identifiers, just not PHI)
        - Health context + strong identifier → RED
        - Health context + weak identifier → ORANGE
        - Health context alone (no identifier) → GREEN or ORANGE based on generalization
        """
        
        # First-person exemption: if talking about yourself, not PHI
        if is_first_person and identifier_score <= 1:
            return 'green'
        
        # De-identified information is safe
        if is_deidentified and identifier_score <= 1:
            return 'green'
        
        # No health context = not PHI (just identifiers alone)
        if health_score == 0:
            if identifier_score >= 2:
                # Strong identifier but no health info - just personal info, not PHI
                # But we'll flag as caution since they might add health info
                return 'orange' if self.sensitivity >= 3 else 'green'
            return 'green'
        
        # Has health context - now check identifiers
        if health_score >= 1:
            # SSN with any health context = always RED
            if any(r.get('subtype') == 'ssn' for r in reasons):
                return 'red'
            
            # Strong identifier + health context = RED (PHI disclosure)
            if identifier_score >= 2:
                return 'red'
            
            # Weak identifier + health context = ORANGE (potential PHI)
            if identifier_score == 1:
                return 'orange'
            
            # Health context alone, no identifiers
            # If explicit patient context without de-identification, be cautious
            has_patient_context = any(
                r.get('subtype') == 'patient_context' for r in reasons
            )
            if has_patient_context and self.sensitivity >= 3:
                return 'orange'
            
            return 'green'
        
        return 'green'
    
    def _format_violations(self, reasons: List[Dict], status: str) -> List[Dict]:
        """Format reasons into backwards-compatible violations format."""
        violations = []
        
        for reason in reasons:
            violations.append({
                'type': reason.get('subtype', reason.get('type')),
                'title': 'Title II',
                'subsection': '45 CFR § 164.514',
                'description': reason.get('description', ''),
                'keywords': reason.get('snippets', []),
                'category': reason.get('type')
            })
        
        return violations


# Initialize rules engine instance
rules_engine = HIPAARulesEngine()

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Landing page."""
    return RedirectResponse(url="/landing")

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "1.0.0"}

# ============================================================================
# ADVANCED CONTEXT-AWARE DETECTION ENGINE
# Reduces false positives by understanding query/educational vs PHI disclosure
# ============================================================================

class AdvancedContextAnalyzer:
    """
    Advanced NLP-based context analyzer to reduce false positives.
    Distinguishes between:
    - PHI disclosure: "Patient John Smith has diabetes"
    - Query about compliance: "Is it HIPAA compliant?"
    - Educational content: "HIPAA requires..."
    - First-person statements: "I have diabetes"
    """
    
    # Query/Educational phrases that should NOT trigger warnings
    QUERY_PATTERNS = [
        # Questions about compliance
        r'\b(?:is|are|was|were|would|should|can|could|will)\s+(?:it|this|that|he|she|they)\s+(?:hipaa|hippa|compliant|legal|allowed|permitted)',
        r'\b(?:what|how|when|where|why)\s+(?:is|are|does|do|can|could|should|will)\s+(?:hipaa|hippa|compliant|legal|allowed)',
        r'\b(?:is|are)\s+(?:hipaa|hippa|compliant|legal|allowed|permitted)',
        r'\b(?:hipaa|hippa)\s+(?:compliant|compliance|legal|allows|requires|mandates|prohibits)',
        r'\b(?:compliant|compliance)\s+(?:with|under)\s+(?:hipaa|hippa)',
        # Educational/Informational
        r'\b(?:hipaa|hippa)\s+(?:requires|mandates|prohibits|allows|permits|states|says|means)',
        r'\b(?:according\s+to|under|per)\s+(?:hipaa|hippa)',
        r'\b(?:what\s+is|what\s+does|explain|tell\s+me\s+about)\s+(?:hipaa|hippa|phi|protected\s+health)',
        # General questions (not PHI disclosure)
        r'\b(?:can\s+you|could\s+you|please|help\s+me)\s+(?:explain|tell|describe|define|what|how)',
        r'\b(?:i\s+(?:want|need|would\s+like)\s+to\s+know|i\s+have\s+a\s+question)\s+about',
    ]
    
    # Context indicators that suggest PHI disclosure (not query)
    PHI_DISCLOSURE_INDICATORS = [
        r'\b(?:patient|client|member)\s+(?:name|is|has|was|diagnosed|admitted|discharged)',
        r'\b(?:my|the|this|our)\s+(?:patient|client|member)',
        r'\b(?:chart|medical\s+record|clinical\s+note|progress\s+note)',
        r'\b(?:ssn|social\s+security|date\s+of\s+birth|dob|mrn|medical\s+record\s+number)',
    ]
    
    # First-person health statements (not PHI about others)
    FIRST_PERSON_HEALTH = [
        r'\b(?:i|i\'m|i\'ve|i\'ll|me|my|myself)\s+(?:have|has|had|am|was|will\s+be)\s+(?:diabetes|cancer|hiv|aids|depression|anxiety|ptsd)',
        r'\b(?:i|i\'m|i\'ve)\s+(?:been\s+)?(?:diagnosed|treated|prescribed|admitted|discharged)',
        r'\b(?:my|i\s+have)\s+(?:condition|diagnosis|treatment|medication|prescription)',
    ]
    
    @staticmethod
    def is_query_or_educational(text: str) -> bool:
        """Check if text is asking about compliance/education rather than disclosing PHI"""
        text_lower = text.lower()
        
        # Check for query patterns
        for pattern in AdvancedContextAnalyzer.QUERY_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        
        # Check for question structure
        question_words = ['what', 'how', 'when', 'where', 'why', 'is', 'are', 'can', 'should', 'would']
        if any(text_lower.strip().startswith(qw) for qw in question_words):
            # If it's a question and contains compliance terms, likely a query
            if any(term in text_lower for term in ['hipaa', 'hippa', 'compliant', 'compliance', 'legal', 'phi', 'protected health']):
                return True
        
        return False
    
    @staticmethod
    def is_first_person_health(text: str) -> bool:
        """Check if text is first-person health statement (not PHI about others)"""
        text_lower = text.lower()
        
        for pattern in AdvancedContextAnalyzer.FIRST_PERSON_HEALTH:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        
        # Check for "I/my" + health terms
        if re.search(r'\b(?:i|i\'m|i\'ve|my|myself)\s+', text_lower) and \
           re.search(r'\b(?:have|has|had|am|was|diagnosed|treatment|medication|condition|disease|disorder)\b', text_lower):
            return True
        
        return False
    
    @staticmethod
    def has_phi_disclosure_context(text: str) -> bool:
        """Check if text has clear indicators of PHI disclosure (not query)"""
        text_lower = text.lower()
        
        for pattern in AdvancedContextAnalyzer.PHI_DISCLOSURE_INDICATORS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def analyze_context(text: str) -> Dict[str, Any]:
        """
        Advanced context analysis to reduce false positives.
        Returns context flags and adjusted risk assessment.
        """
        is_query = AdvancedContextAnalyzer.is_query_or_educational(text)
        is_first_person = AdvancedContextAnalyzer.is_first_person_health(text)
        has_phi_context = AdvancedContextAnalyzer.has_phi_disclosure_context(text)
        
        # Determine if this is likely a false positive
        is_false_positive = False
        reason = None
        
        if is_query and not has_phi_context:
            is_false_positive = True
            reason = "Query about compliance/education, not PHI disclosure"
        elif is_first_person and not has_phi_context:
            is_false_positive = True
            reason = "First-person health statement, not PHI about others"
        
        return {
            'is_query': is_query,
            'is_first_person_health': is_first_person,
            'has_phi_context': has_phi_context,
            'is_false_positive': is_false_positive,
            'reason': reason
        }


@app.post("/api/scan", response_model=ScanResult)
async def scan_text(request: ScanRequest):
    """
    Scan text for HIPAA Privacy Rule PHI disclosure with advanced context analysis.
    
    Uses:
    1. Basic regex pattern matching (HIPAARulesEngine)
    2. Advanced context analysis to reduce false positives
    3. Query/educational phrase detection
    4. First-person health statement detection
    
    Returns:
        - status: green (safe), orange (caution), red (likely PHI disclosure)
        - violations: list of detected issues (backwards compatible)
        - reasons: structured list of health/identifier findings
        - scores: health_score and identifier_score for transparency
    """
    # Step 1: Advanced context analysis (reduce false positives)
    context_analysis = AdvancedContextAnalyzer.analyze_context(request.text)
    
    # Step 2: If it's clearly a query/educational (not PHI disclosure), return green
    if context_analysis['is_false_positive']:
        return ScanResult(
            status='green',
            violations=[],
            scan_time=0.001,
            scores={'health_score': 0, 'identifier_score': 0},
            reasons=[{
                'type': 'context',
                'subtype': 'query_educational',
                'description': context_analysis['reason'],
                'snippets': [],
                'score': 0
            }]
        )
    
    # Step 3: Run standard HIPAA engine
    engine = HIPAARulesEngine(request.sensitivity)
    result = engine.scan(request.text)
    
    # Step 4: Apply context-based adjustments
    original_status = result['status']
    
    # If context analysis suggests it's first-person health (not PHI about others)
    # and we got orange/red, downgrade to green
    if context_analysis['is_first_person_health'] and \
       result['status'] in ['orange', 'red'] and \
       not context_analysis['has_phi_context']:
        result['status'] = 'green'
        result['reasons'].append({
            'type': 'context',
            'subtype': 'first_person_exemption',
            'description': 'First-person health statement, not PHI about others',
            'snippets': [],
            'score': 0
        })
    
    # If it's a query but we still got orange/red, downgrade to green
    elif context_analysis['is_query'] and result['status'] in ['orange', 'red']:
        result['status'] = 'green'
        result['reasons'].append({
            'type': 'context',
            'subtype': 'query_exemption',
            'description': 'Query about compliance, not PHI disclosure',
            'snippets': [],
            'score': 0
        })
    
    # Update statistics (use original status for stats, not adjusted)
    store.stats['total_scans'] += 1
    store.stats[f"{original_status}_count"] += 1
    
    if request.platform:
        store.stats['violations_by_platform'][request.platform][original_status] += 1
    
    for violation in result.get('violations', []):
        store.stats['violations_by_title'][violation.get('title', 'Title II')] += 1
        store.stats['violations_by_type'][violation.get('type', 'unknown')] += 1
    
    return ScanResult(
        status=result['status'],
        violations=result.get('violations', []),
        scan_time=result['scan_time'],
        scores=result.get('scores'),
        reasons=result.get('reasons')
    )

@app.post("/api/submit-event")
async def log_submit_event(event: SubmitEventRequest):
    """
    Log when a user submits despite a warning (override).
    """
    if event.status in ['orange', 'red']:
        store.stats['overrides'][event.status] += 1
    
    return {"logged": True}

@app.get("/api/stats")
async def get_stats():
    """
    Get aggregated statistics for the admin dashboard.
    """
    return store.get_stats_summary()

@app.get("/api/settings")
async def get_settings():
    """Get current settings."""
    return {
        "sensitivity_level": store.sensitivity_level,
        "text_red_behavior": store.text_red_behavior,
        "upload_red_behavior": store.upload_red_behavior,
        "pdf_red_behavior": store.upload_red_behavior  # Backwards compatibility
    }

@app.post("/api/settings")
async def update_settings(settings: SettingsUpdate):
    """Update settings."""
    if settings.sensitivity_level is not None:
        store.sensitivity_level = settings.sensitivity_level
    # Text message behavior
    if settings.text_red_behavior is not None:
        if settings.text_red_behavior in ['block', 'warn_with_override', 'log_only']:
            store.text_red_behavior = settings.text_red_behavior
    # File upload behavior - accept either upload_red_behavior or pdf_red_behavior
    behavior = settings.upload_red_behavior or settings.pdf_red_behavior
    if behavior is not None:
        if behavior in ['block', 'warn_with_override', 'log_only']:
            store.upload_red_behavior = behavior
    return {
        "success": True,
        "sensitivity_level": store.sensitivity_level,
        "text_red_behavior": store.text_red_behavior,
        "upload_red_behavior": store.upload_red_behavior,
        "pdf_red_behavior": store.upload_red_behavior  # Backwards compatibility
    }


class FileScanEvent(BaseModel):
    status: str  # green, orange, red
    platform: str
    outcome: str  # 'allowed', 'blocked', 'override', 'unscannable'
    filename: Optional[str] = None  # Just filename, not content
    file_type: Optional[str] = None  # 'pdf', 'txt', 'docx', 'image', etc.
    text_length: Optional[int] = None


@app.post("/api/file-event")
async def log_file_event(event: FileScanEvent):
    """
    Log a file scan event for analytics.
    Called by the extension after scanning any uploaded file.
    """
    # Update file stats
    store.stats['file_scans'] += 1
    
    if event.status == 'green':
        store.stats['file_green'] += 1
    elif event.status == 'orange':
        store.stats['file_orange'] += 1
    elif event.status == 'red':
        store.stats['file_red'] += 1
        
        if event.outcome == 'blocked':
            store.stats['file_blocked'] += 1
        elif event.outcome == 'override':
            store.stats['file_overrides'] += 1
    
    # Track by file type
    if event.file_type:
        store.stats['file_by_type'][event.file_type]['scans'] += 1
        store.stats['file_by_type'][event.file_type][event.status] += 1
    
    # Also track by platform
    if event.platform:
        store.stats['violations_by_platform'][event.platform][event.status] += 1
    
    return {"logged": True, "file_stats": {
        "total": store.stats['file_scans'],
        "blocked": store.stats['file_blocked'],
        "overrides": store.stats['file_overrides']
    }}


# Backwards compatibility alias
@app.post("/api/pdf-event")
async def log_pdf_event_compat(event: FileScanEvent):
    """Backwards compatibility alias for /api/file-event."""
    event.file_type = event.file_type or 'pdf'
    return await log_file_event(event)


# ============================================================================
# DE-IDENTIFICATION COACHING EVENTS
# ============================================================================

class CoachingEvent(BaseModel):
    """Coaching event data - NO PHI stored, only metadata."""
    action: str  # 'shown', 'used_safer_version', 'kept_original', 'undid_safer_version'
    status: str  # 'orange' or 'red'
    platform: Optional[str] = None
    timestamp: Optional[str] = None


@app.post("/api/coaching-event")
async def log_coaching_event(event: CoachingEvent):
    """
    Log a de-identification coaching event.
    Only logs metadata - no PHI content is stored.
    
    Actions:
    - 'shown': Coaching suggestions were displayed to user
    - 'used_safer_version': User chose to use the de-identified version
    - 'kept_original': User chose to keep their original text
    - 'undid_safer_version': User undid the safer version replacement
    """
    action = event.action
    status = event.status
    
    # Track coaching shown
    if action == 'shown':
        store.stats['coaching_shown'] += 1
        if status in store.stats['coaching_by_status']:
            store.stats['coaching_by_status'][status] += 1
    
    # Track user chose safer version
    elif action == 'used_safer_version':
        store.stats['coaching_used_safer'] += 1
        if status in store.stats['coaching_safer_used_by_status']:
            store.stats['coaching_safer_used_by_status'][status] += 1
    
    # Track user kept original
    elif action == 'kept_original':
        store.stats['coaching_kept_original'] += 1
    
    # Track undo
    elif action == 'undid_safer_version':
        store.stats['coaching_undid'] += 1
    
    # Track by platform
    if event.platform:
        store.stats['violations_by_platform'][event.platform][status] += 0  # Don't double count
    
    return {
        "logged": True,
        "coaching_stats": {
            "shown": store.stats['coaching_shown'],
            "used_safer": store.stats['coaching_used_safer'],
            "kept_original": store.stats['coaching_kept_original'],
            "safer_adoption_rate": round(
                store.stats['coaching_used_safer'] / max(store.stats['coaching_shown'], 1) * 100, 1
            )
        }
    }

@app.post("/api/feedback")
async def submit_feedback(feedback: FeedbackRequest):
    """
    Submit user feedback for false positives/negatives.
    Used for automated training and pattern improvement.
    """
    if not feedback.timestamp:
        feedback.timestamp = datetime.utcnow().isoformat()
    
    feedback_entry = {
        'text': feedback.text[:500],  # Truncate for storage
        'detected_status': feedback.detected_status,
        'expected_status': feedback.expected_status,
        'feedback_type': feedback.feedback_type,
        'platform': feedback.platform or 'unknown',
        'timestamp': feedback.timestamp,
        'detected_reasons': feedback.detected_reasons or []
    }
    
    if feedback.feedback_type == 'false_positive':
        store.stats['feedback']['false_positives'].append(feedback_entry)
    elif feedback.feedback_type == 'false_negative':
        store.stats['feedback']['false_negatives'].append(feedback_entry)
    
    store.stats['feedback']['total_feedback'] += 1
    
    # Keep only last 1000 feedback entries per type
    if len(store.stats['feedback']['false_positives']) > 1000:
        store.stats['feedback']['false_positives'] = store.stats['feedback']['false_positives'][-1000:]
    if len(store.stats['feedback']['false_negatives']) > 1000:
        store.stats['feedback']['false_negatives'] = store.stats['feedback']['false_negatives'][-1000:]
    
    return {
        "logged": True,
        "message": "Feedback received. Thank you for helping improve detection accuracy!",
        "total_feedback": store.stats['feedback']['total_feedback']
    }

@app.get("/api/feedback/stats")
async def get_feedback_stats(request: Request):
    """Get feedback statistics (admin only)"""
    username = verify_session(request)
    if not username:
        raise HTTPException(status_code=401, detail="Admin authentication required")
    
    return {
        "total_feedback": store.stats['feedback']['total_feedback'],
        "false_positives_count": len(store.stats['feedback']['false_positives']),
        "false_negatives_count": len(store.stats['feedback']['false_negatives']),
        "recent_false_positives": store.stats['feedback']['false_positives'][-10:],
        "recent_false_negatives": store.stats['feedback']['false_negatives'][-10:]
    }

# ============================================================================
# RULES API - Backend-updatable HIPAA rules
# ============================================================================

class RulesUpdate(BaseModel):
    """Model for updating rules"""
    strong_identifiers: Optional[Dict[str, Any]] = None
    weak_identifiers: Optional[Dict[str, Any]] = None
    health_context: Optional[Dict[str, Any]] = None
    thresholds: Optional[Dict[str, Any]] = None
    custom_keywords: Optional[List[str]] = None

class PatternUpdate(BaseModel):
    """Model for adding/removing individual patterns"""
    category: str  # 'strong', 'weak', 'health'
    identifier: str  # e.g., 'full_name', 'ssn'
    pattern: Optional[str] = None  # For adding
    pattern_index: Optional[int] = None  # For removing

@app.get("/api/rules")
async def get_rules(version: Optional[int] = None):
    """
    Get current HIPAA rules.
    
    If version is provided and matches current version, returns 304 Not Modified.
    Extensions should cache rules locally and only fetch when version changes.
    """
    current_rules = rules_store.get_rules()
    
    # If client has current version, return minimal response
    if version is not None and version >= current_rules['version']:
        return {
            "status": "current",
            "version": current_rules['version'],
            "message": "Rules are up to date"
        }
    
    return {
        "status": "ok",
        **current_rules
    }

@app.get("/api/rules/version")
async def get_rules_version():
    """Quick endpoint to check current rules version"""
    return {
        "version": rules_store.version,
        "last_updated": rules_store.last_updated
    }

@app.post("/api/rules")
async def update_rules(request: Request, updates: RulesUpdate):
    """Update HIPAA rules (admin only)"""
    # Verify admin session
    username = verify_session(request)
    if not username:
        raise HTTPException(status_code=401, detail="Admin authentication required")
    
    # Apply updates
    update_dict = updates.dict(exclude_none=True)
    if update_dict:
        rules_store.update_rules(update_dict)
    
    return {
        "status": "ok",
        "message": "Rules updated successfully",
        "version": rules_store.version,
        "last_updated": rules_store.last_updated
    }

@app.post("/api/rules/pattern/add")
async def add_pattern(request: Request, update: PatternUpdate):
    """Add a new pattern to an identifier (admin only)"""
    username = verify_session(request)
    if not username:
        raise HTTPException(status_code=401, detail="Admin authentication required")
    
    if not update.pattern:
        raise HTTPException(status_code=400, detail="Pattern is required")
    
    success = rules_store.add_pattern(update.category, update.identifier, update.pattern)
    if not success:
        raise HTTPException(status_code=400, detail="Invalid category or identifier")
    
    return {
        "status": "ok",
        "message": f"Pattern added to {update.category}/{update.identifier}",
        "version": rules_store.version
    }

@app.post("/api/rules/pattern/remove")
async def remove_pattern(request: Request, update: PatternUpdate):
    """Remove a pattern from an identifier by index (admin only)"""
    username = verify_session(request)
    if not username:
        raise HTTPException(status_code=401, detail="Admin authentication required")
    
    if update.pattern_index is None:
        raise HTTPException(status_code=400, detail="Pattern index is required")
    
    success = rules_store.remove_pattern(update.category, update.identifier, update.pattern_index)
    if not success:
        raise HTTPException(status_code=400, detail="Invalid category, identifier, or index")
    
    return {
        "status": "ok",
        "message": f"Pattern removed from {update.category}/{update.identifier}",
        "version": rules_store.version
    }

# ============================================================================
# ADMIN AUTHENTICATION
# ============================================================================

def verify_session(request: Request) -> Optional[str]:
    """Verify admin session from cookie."""
    session_token = request.cookies.get("session")
    if not session_token or session_token not in store.sessions:
        return None
    
    session = store.sessions[session_token]
    if datetime.now() > session['expires']:
        del store.sessions[session_token]
        return None
    
    return session['username']

@app.post("/api/login")
async def login(response: Response, username: str = Form(...), password: str = Form(...)):
    """Admin login endpoint."""
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    if username not in ADMIN_CREDENTIALS or ADMIN_CREDENTIALS[username] != password_hash:
        return RedirectResponse(url="/login?error=1", status_code=303)
    
    # Create session
    session_token = secrets.token_urlsafe(32)
    store.sessions[session_token] = {
        'username': username,
        'expires': datetime.now() + timedelta(hours=8)
    }
    
    response = RedirectResponse(url="/admin", status_code=303)
    response.set_cookie("session", session_token, httponly=True, samesite="lax")
    return response

@app.get("/api/logout")
async def logout(request: Request):
    """Admin logout endpoint."""
    session_token = request.cookies.get("session")
    if session_token and session_token in store.sessions:
        del store.sessions[session_token]
    
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("session")
    return response

# ============================================================================
# HTML PAGES (Landing, Login, Admin Dashboard)
# ============================================================================

LANDING_PAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Korguard Beacon - AI Input Compliance Scanner</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --primary: #0ea5e9;
            --primary-dark: #0284c7;
            --beacon-blue: #1e40af;
            --beacon-light: #3b82f6;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #0f172a;
            --dark-lighter: #1e293b;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
        }
        
        body {
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--dark);
            color: var(--text);
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        /* Background effects */
        .bg-effects {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            z-index: -1;
            overflow: hidden;
        }
        
        .bg-gradient {
            position: absolute;
            width: 800px;
            height: 800px;
            border-radius: 50%;
            filter: blur(120px);
            opacity: 0.15;
        }
        
        .bg-gradient-1 {
            top: -200px;
            left: -200px;
            background: var(--beacon-blue);
        }
        
        .bg-gradient-2 {
            bottom: -200px;
            right: -200px;
            background: var(--primary);
        }
        
        .bg-grid {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: 
                linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px);
            background-size: 60px 60px;
        }
        
        /* Header */
        header {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 100;
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            backdrop-filter: blur(12px);
            background: rgba(15, 23, 42, 0.8);
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        
        .logo-group {
            display: flex;
            align-items: center;
            gap: 24px;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .logo-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--success), #16a34a);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .logo-icon svg {
            width: 24px;
            height: 24px;
            fill: white;
        }
        
        .logo-text {
            font-size: 20px;
            font-weight: 700;
            letter-spacing: -0.02em;
        }
        
        .logo-text span {
            color: var(--success);
        }
        
        .divider {
            width: 1px;
            height: 30px;
            background: rgba(255,255,255,0.1);
        }
        
        .beacon-logo {
            font-size: 14px;
            color: var(--text-muted);
        }
        
        .admin-link {
            color: var(--text-muted);
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
            padding: 10px 20px;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            transition: all 0.2s;
        }
        
        .admin-link:hover {
            color: var(--text);
            border-color: rgba(255,255,255,0.2);
            background: rgba(255,255,255,0.05);
        }
        
        /* Hero */
        .hero {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 120px 40px 80px;
        }
        
        .hero-content {
            max-width: 900px;
            text-align: center;
        }
        
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            border-radius: 100px;
            font-size: 13px;
            font-weight: 500;
            color: var(--success);
            margin-bottom: 32px;
        }
        
        .badge-dot {
            width: 6px;
            height: 6px;
            background: var(--success);
            border-radius: 50%;
            animation: pulse 2s ease-in-out infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        h1 {
            font-size: 64px;
            font-weight: 800;
            line-height: 1.1;
            letter-spacing: -0.03em;
            margin-bottom: 24px;
        }
        
        h1 .gradient {
            background: linear-gradient(135deg, var(--beacon-light), var(--primary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .subtitle {
            font-size: 20px;
            color: var(--text-muted);
            line-height: 1.6;
            max-width: 600px;
            margin: 0 auto 48px;
        }
        
        .cta-group {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 16px;
            flex-wrap: wrap;
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 16px 32px;
            font-size: 16px;
            font-weight: 600;
            text-decoration: none;
            border-radius: 12px;
            transition: all 0.2s;
            cursor: pointer;
            border: none;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--success), #16a34a);
            color: white;
            box-shadow: 0 4px 20px rgba(34, 197, 94, 0.3);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 30px rgba(34, 197, 94, 0.4);
        }
        
        .btn-secondary {
            background: rgba(255,255,255,0.05);
            color: var(--text);
            border: 1px solid rgba(255,255,255,0.1);
        }
        
        .btn-secondary:hover {
            background: rgba(255,255,255,0.1);
            border-color: rgba(255,255,255,0.2);
        }
        
        .btn svg {
            width: 20px;
            height: 20px;
        }
        
        /* Features */
        .features {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 24px;
            max-width: 1000px;
            margin: 80px auto 0;
            padding: 0 40px;
        }
        
        .feature-card {
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 16px;
            padding: 28px;
            transition: all 0.3s;
        }
        
        .feature-card:hover {
            background: rgba(255,255,255,0.05);
            border-color: rgba(255,255,255,0.1);
            transform: translateY(-4px);
        }
        
        .feature-icon {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 20px;
            font-size: 24px;
        }
        
        .feature-icon.green { background: rgba(34, 197, 94, 0.15); }
        .feature-icon.orange { background: rgba(245, 158, 11, 0.15); }
        .feature-icon.blue { background: rgba(14, 165, 233, 0.15); }
        
        .feature-card h3 {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 10px;
        }
        
        .feature-card p {
            font-size: 14px;
            color: var(--text-muted);
            line-height: 1.6;
        }
        
        /* Demo */
        .demo-section {
            max-width: 800px;
            margin: 100px auto;
            padding: 0 40px;
        }
        
        .demo-card {
            background: var(--dark-lighter);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 20px;
            overflow: hidden;
        }
        
        .demo-header {
            padding: 20px 24px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .demo-dots {
            display: flex;
            gap: 8px;
        }
        
        .demo-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }
        
        .demo-dot.red { background: #ef4444; }
        .demo-dot.yellow { background: #eab308; }
        .demo-dot.green { background: #22c55e; }
        
        .demo-title {
            flex: 1;
            text-align: center;
            font-size: 13px;
            color: var(--text-muted);
        }
        
        .demo-content {
            padding: 32px;
        }
        
        .demo-input {
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 16px;
            position: relative;
        }
        
        .demo-text {
            font-size: 15px;
            line-height: 1.6;
            color: var(--text);
        }
        
        .demo-text .highlight {
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            padding: 2px 6px;
            border-radius: 4px;
        }
        
        .demo-shield {
            position: absolute;
            top: -16px;
            right: -16px;
            width: 48px;
            height: 48px;
            background: rgba(239, 68, 68, 0.15);
            border: 2px solid #ef4444;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #ef4444;
            animation: pulse-ring 2s ease-out infinite;
        }
        
        @keyframes pulse-ring {
            0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
            100% { box-shadow: 0 0 0 20px rgba(239, 68, 68, 0); }
        }
        
        .demo-shield svg {
            width: 24px;
            height: 24px;
        }
        
        .demo-tooltip {
            margin-top: 20px;
            background: rgba(0,0,0,0.4);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-left: 4px solid #ef4444;
            border-radius: 8px;
            padding: 16px;
        }
        
        .demo-tooltip-header {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 12px;
            font-weight: 600;
            color: #fca5a5;
        }
        
        .demo-tooltip-content {
            font-size: 13px;
            color: var(--text-muted);
            line-height: 1.6;
        }
        
        .demo-tooltip-content code {
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
        }
        
        /* Footer */
        footer {
            padding: 40px;
            text-align: center;
            border-top: 1px solid rgba(255,255,255,0.05);
        }
        
        footer p {
            font-size: 13px;
            color: var(--text-muted);
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            h1 { font-size: 40px; }
            .subtitle { font-size: 16px; }
            .features { grid-template-columns: 1fr; }
            header { padding: 16px 20px; }
            .hero { padding: 100px 20px 60px; }
            .logo-group { gap: 12px; }
            .beacon-logo { display: none; }
            .divider { display: none; }
        }
    </style>
</head>
<body>
    <div class="bg-effects">
        <div class="bg-gradient bg-gradient-1"></div>
        <div class="bg-gradient bg-gradient-2"></div>
        <div class="bg-grid"></div>
    </div>
    
    <header>
        <div class="logo-group">
            <div class="logo">
                <div class="logo-icon">
                    <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path d="M12 2L4 5v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V5l-8-3z"/>
                    </svg>
                </div>
                <span class="logo-text">Korguard <span>Beacon</span></span>
            </div>
            <div class="divider"></div>
            <span class="beacon-logo">Beacon Health System</span>
        </div>
        <a href="/login" class="admin-link">Admin Sign In</a>
    </header>
    
    <main class="hero">
        <div class="hero-content">
            <div class="badge">
                <span class="badge-dot"></span>
                Real-time HIPAA Compliance
            </div>
            
            <h1>
                Protect Patient Privacy<br>
                <span class="gradient">When Using AI</span>
            </h1>
            
            <p class="subtitle">
                Korguard Beacon scans your AI prompts in real-time for HIPAA-sensitive 
                information, warning you before protected health information is shared 
                with LLM services.
            </p>
            
            <div class="cta-group">
                <a href="https://chrome.google.com/webstore" target="_blank" class="btn btn-primary">
                    <svg viewBox="0 0 24 24" fill="currentColor">
                        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>
                    </svg>
                    Install Extension
                </a>
                <a href="#demo" class="btn btn-secondary">
                    See How It Works
                </a>
            </div>
            
            <div class="features">
                <div class="feature-card">
                    <div class="feature-icon green">🛡️</div>
                    <h3>Real-time Scanning</h3>
                    <p>Monitors your input as you type, providing instant feedback before you submit.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon orange">⚡</div>
                    <h3>18 PHI Identifiers</h3>
                    <p>Detects all HIPAA-defined protected health information identifiers automatically.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon blue">📊</div>
                    <h3>Admin Dashboard</h3>
                    <p>Compliance officers can monitor usage patterns and adjust sensitivity levels.</p>
                </div>
            </div>
        </div>
    </main>
    
    <section class="demo-section" id="demo">
        <div class="demo-card">
            <div class="demo-header">
                <div class="demo-dots">
                    <span class="demo-dot red"></span>
                    <span class="demo-dot yellow"></span>
                    <span class="demo-dot green"></span>
                </div>
                <span class="demo-title">ChatGPT</span>
            </div>
            <div class="demo-content">
                <div class="demo-input">
                    <div class="demo-text">
                        Can you help me write a summary for my patient 
                        <span class="highlight">John Smith</span>? He was diagnosed with 
                        <span class="highlight">Type 2 Diabetes</span> on 
                        <span class="highlight">03/15/2024</span> and his SSN is 
                        <span class="highlight">123-45-6789</span>.
                    </div>
                    <div class="demo-shield">
                        <svg viewBox="0 0 24 24" fill="currentColor">
                            <path d="M12 2L4 5v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V5l-8-3z"/>
                        </svg>
                    </div>
                </div>
                <div class="demo-tooltip">
                    <div class="demo-tooltip-header">
                        🚨 HIPAA Violation Detected
                    </div>
                    <div class="demo-tooltip-content">
                        <strong>Title II - Privacy Rule (45 CFR § 164.514)</strong><br><br>
                        This message contains Protected Health Information (PHI):<br>
                        • Patient name: <code>John Smith</code><br>
                        • Medical diagnosis: <code>Type 2 Diabetes</code><br>
                        • Date: <code>03/15/2024</code><br>
                        • SSN: <code>123-45-6789</code>
                    </div>
                </div>
            </div>
        </div>
    </section>
    
    <footer>
        <p>© 2024 Korguard Beacon • Beacon Health System • HIPAA Compliance Tool</p>
    </footer>
</body>
</html>
"""

LOGIN_PAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - Korguard Beacon</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .login-container {
            width: 100%;
            max-width: 400px;
            padding: 20px;
        }
        
        .login-card {
            background: #1e293b;
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 20px;
            padding: 40px;
        }
        
        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            margin-bottom: 32px;
        }
        
        .logo-icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, #22c55e, #16a34a);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .logo-icon svg {
            width: 28px;
            height: 28px;
            fill: white;
        }
        
        .logo-text {
            font-size: 24px;
            font-weight: 700;
        }
        
        .logo-text span { color: #22c55e; }
        
        h1 {
            text-align: center;
            font-size: 20px;
            margin-bottom: 8px;
        }
        
        .subtitle {
            text-align: center;
            color: #94a3b8;
            font-size: 14px;
            margin-bottom: 32px;
        }
        
        .error-message {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fca5a5;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 14px;
            margin-bottom: 20px;
            display: none;
        }
        
        .error-message.show { display: block; }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            font-size: 13px;
            font-weight: 500;
            margin-bottom: 8px;
            color: #94a3b8;
        }
        
        input {
            width: 100%;
            padding: 14px 16px;
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 10px;
            color: #e2e8f0;
            font-size: 15px;
            font-family: inherit;
            transition: all 0.2s;
        }
        
        input:focus {
            outline: none;
            border-color: #22c55e;
            box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.1);
        }
        
        button {
            width: 100%;
            padding: 14px 24px;
            background: linear-gradient(135deg, #22c55e, #16a34a);
            border: none;
            border-radius: 10px;
            color: white;
            font-size: 15px;
            font-weight: 600;
            font-family: inherit;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 20px rgba(34, 197, 94, 0.3);
        }
        
        .back-link {
            display: block;
            text-align: center;
            margin-top: 24px;
            color: #64748b;
            text-decoration: none;
            font-size: 14px;
        }
        
        .back-link:hover { color: #94a3b8; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-card">
            <div class="logo">
                <div class="logo-icon">
                    <svg viewBox="0 0 24 24">
                        <path d="M12 2L4 5v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V5l-8-3z"/>
                    </svg>
                </div>
                <span class="logo-text">Korguard <span>Beacon</span></span>
            </div>
            
            <h1>Admin Sign In</h1>
            <p class="subtitle">Access the compliance dashboard</p>
            
            <div class="error-message" id="error">
                Invalid username or password. Please try again.
            </div>
            
            <form action="/api/login" method="POST">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required autocomplete="username">
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required autocomplete="current-password">
                </div>
                <button type="submit">Sign In</button>
            </form>
            
            <a href="/" class="back-link">← Back to home</a>
        </div>
    </div>
    
    <script>
        // Show error if redirected with error param
        if (window.location.search.includes('error=1')) {
            document.getElementById('error').classList.add('show');
        }
    </script>
</body>
</html>
"""

ADMIN_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Korguard Beacon</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --green: #22c55e;
            --orange: #f59e0b;
            --red: #ef4444;
            --dark: #0f172a;
            --dark-lighter: #1e293b;
            --dark-card: #1e293b;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --border: rgba(255,255,255,0.08);
        }
        
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background: var(--dark);
            color: var(--text);
            min-height: 100vh;
        }
        
        /* Header */
        header {
            background: var(--dark-lighter);
            border-bottom: 1px solid var(--border);
            padding: 16px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .logo-icon {
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, var(--green), #16a34a);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .logo-icon svg {
            width: 20px;
            height: 20px;
            fill: white;
        }
        
        .logo-text {
            font-size: 18px;
            font-weight: 700;
        }
        
        .logo-text span { color: var(--green); }
        
        .header-right {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .user-info {
            font-size: 14px;
            color: var(--text-muted);
        }
        
        .logout-btn {
            padding: 8px 16px;
            background: transparent;
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-muted);
            font-size: 13px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s;
        }
        
        .logout-btn:hover {
            border-color: var(--red);
            color: var(--red);
        }
        
        /* Main */
        main {
            padding: 32px;
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .page-title {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 8px;
        }
        
        .page-subtitle {
            color: var(--text-muted);
            font-size: 15px;
            margin-bottom: 32px;
        }
        
        /* Cards Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 32px;
        }
        
        .stat-card {
            background: var(--dark-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
        }
        
        .stat-label {
            font-size: 13px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: 700;
        }
        
        .stat-value.green { color: var(--green); }
        .stat-value.orange { color: var(--orange); }
        .stat-value.red { color: var(--red); }
        
        /* Charts Grid */
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 32px;
        }
        
        .chart-card {
            background: var(--dark-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
        }
        
        .chart-title {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 20px;
        }
        
        .chart-container {
            height: 250px;
            position: relative;
        }
        
        /* Sensitivity Settings */
        .settings-card {
            background: var(--dark-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 32px;
        }
        
        .settings-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 20px;
        }
        
        .sensitivity-levels {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
        }
        
        .sensitivity-btn {
            background: rgba(255,255,255,0.03);
            border: 2px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            cursor: pointer;
            transition: all 0.2s;
            text-align: center;
            color: var(--text);
        }
        
        .sensitivity-btn:hover {
            background: rgba(255,255,255,0.05);
        }
        
        .sensitivity-btn.active {
            border-color: var(--green);
            background: rgba(34, 197, 94, 0.1);
        }
        
        .sensitivity-btn .level {
            font-size: 28px;
            font-weight: 700;
            color: white;
        }
        
        .sensitivity-btn .label {
            font-size: 14px;
            color: var(--text-muted);
            margin-top: 4px;
        }
        
        .sensitivity-btn.active .label {
            color: var(--green);
        }
        
        .sensitivity-btn .desc {
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 8px;
            line-height: 1.4;
        }
        
        /* Tables */
        .table-card {
            background: var(--dark-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            overflow: hidden;
        }
        
        .table-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
        }
        
        .table-title {
            font-size: 16px;
            font-weight: 600;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 16px 24px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        td {
            font-size: 14px;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 100px;
            font-size: 12px;
            font-weight: 500;
        }
        
        .badge.green { background: rgba(34, 197, 94, 0.15); color: var(--green); }
        .badge.orange { background: rgba(245, 158, 11, 0.15); color: var(--orange); }
        .badge.red { background: rgba(239, 68, 68, 0.15); color: var(--red); }
        
        /* Responsive */
        @media (max-width: 1024px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .charts-grid { grid-template-columns: 1fr; }
            .sensitivity-levels { grid-template-columns: repeat(2, 1fr); }
        }
        
        @media (max-width: 640px) {
            .stats-grid { grid-template-columns: 1fr; }
            main { padding: 20px; }
        }
    </style>
</head>
<body>
    <header>
        <div class="logo">
            <div class="logo-icon">
                <svg viewBox="0 0 24 24">
                    <path d="M12 2L4 5v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V5l-8-3z"/>
                </svg>
            </div>
            <span class="logo-text">Korguard <span>Beacon</span></span>
        </div>
        <div class="header-right">
            <span class="user-info">Logged in as <strong>Admin</strong></span>
            <a href="/api/logout" class="logout-btn">Sign Out</a>
        </div>
    </header>
    
    <main>
        <h1 class="page-title">Compliance Dashboard</h1>
        <p class="page-subtitle">Monitor HIPAA compliance across your organization's AI usage</p>
        
        <!-- Stats Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Scans</div>
                <div class="stat-value" id="totalScans">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Safe (Green)</div>
                <div class="stat-value green" id="greenPercent">0%</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Caution (Orange)</div>
                <div class="stat-value orange" id="orangePercent">0%</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Violations (Red)</div>
                <div class="stat-value red" id="redPercent">0%</div>
            </div>
        </div>
        
        <!-- Charts -->
        <div class="charts-grid">
            <div class="chart-card">
                <h3 class="chart-title">Status Distribution</h3>
                <div class="chart-container">
                    <canvas id="statusChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3 class="chart-title">Violations by HIPAA Title</h3>
                <div class="chart-container">
                    <canvas id="titleChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- File Upload Stats -->
        <div class="charts-grid" style="margin-top: 32px;">
            <div class="chart-card">
                <h3 class="chart-title">📁 File Upload Scanning</h3>
                <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">PDFs, documents, text files, and more</p>
                <div class="stats-grid" style="grid-template-columns: repeat(2, 1fr); gap: 12px;">
                    <div class="stat-card" style="padding: 16px;">
                        <div class="stat-label">Files Scanned</div>
                        <div class="stat-value" id="fileTotal" style="font-size: 24px;">0</div>
                    </div>
                    <div class="stat-card" style="padding: 16px;">
                        <div class="stat-label">RED Files Blocked</div>
                        <div class="stat-value red" id="fileBlocked" style="font-size: 24px;">0</div>
                    </div>
                </div>
                <div style="display: flex; gap: 16px; margin-top: 16px;">
                    <div style="flex: 1; text-align: center;">
                        <div style="font-size: 20px; font-weight: 700; color: var(--green);" id="fileGreen">0</div>
                        <div style="font-size: 11px; color: var(--text-muted);">Safe</div>
                    </div>
                    <div style="flex: 1; text-align: center;">
                        <div style="font-size: 20px; font-weight: 700; color: var(--orange);" id="fileOrange">0</div>
                        <div style="font-size: 11px; color: var(--text-muted);">Caution</div>
                    </div>
                    <div style="flex: 1; text-align: center;">
                        <div style="font-size: 20px; font-weight: 700; color: var(--red);" id="fileRed">0</div>
                        <div style="font-size: 11px; color: var(--text-muted);">PHI Detected</div>
                    </div>
                    <div style="flex: 1; text-align: center;">
                        <div style="font-size: 20px; font-weight: 700; color: #f59e0b;" id="fileOverrides">0</div>
                        <div style="font-size: 11px; color: var(--text-muted);">Overrides</div>
                    </div>
                </div>
            </div>
            <div class="chart-card">
                <h3 class="chart-title">🔒 Upload RED Behavior</h3>
                <p style="font-size: 13px; color: var(--text-muted); margin: 12px 0 16px;">
                    Configure what happens when a user tries to upload ANY file containing high-confidence PHI.
                </p>
                <div class="sensitivity-levels" id="uploadBehaviorLevels" style="grid-template-columns: repeat(3, 1fr);">
                    <button class="sensitivity-btn upload-behavior-btn" data-behavior="block">
                        <div class="level">🚫</div>
                        <div class="label">Block</div>
                        <div class="desc" style="font-size: 10px;">Prevent upload entirely</div>
                    </button>
                    <button class="sensitivity-btn upload-behavior-btn active" data-behavior="warn_with_override">
                        <div class="level">⚠️</div>
                        <div class="label">Warn + Override</div>
                        <div class="desc" style="font-size: 10px;">Show dialog, allow bypass</div>
                    </button>
                    <button class="sensitivity-btn upload-behavior-btn" data-behavior="log_only">
                        <div class="level">📝</div>
                        <div class="label">Log Only</div>
                        <div class="desc" style="font-size: 10px;">Allow upload, log event</div>
                    </button>
                </div>
                <p style="font-size: 11px; color: #64748b; margin-top: 16px; line-height: 1.5;" id="uploadBehaviorDesc">
                    Current: Users will see a strong warning dialog but can choose to continue uploading.
                </p>
            </div>
        </div>
        
        <!-- Text Message RED Behavior -->
        <div class="settings-card">
            <h3 class="settings-title">💬 Text Message RED Behavior</h3>
            <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
                Configure what happens when a user tries to SEND a text message containing high-confidence PHI.
            </p>
            <div class="sensitivity-levels" id="textBehaviorLevels" style="grid-template-columns: repeat(3, 1fr);">
                <button class="sensitivity-btn text-behavior-btn" data-behavior="block">
                    <div class="level">🚫</div>
                    <div class="label">Block</div>
                    <div class="desc">Prevent sending entirely</div>
                </button>
                <button class="sensitivity-btn text-behavior-btn active" data-behavior="warn_with_override">
                    <div class="level">⚠️</div>
                    <div class="label">Warn + Override</div>
                    <div class="desc">Show dialog, allow bypass</div>
                </button>
                <button class="sensitivity-btn text-behavior-btn" data-behavior="log_only">
                    <div class="level">📝</div>
                    <div class="label">Log Only</div>
                    <div class="desc">Allow send, log event</div>
                </button>
            </div>
            <p style="font-size: 11px; color: #64748b; margin-top: 16px; line-height: 1.5;" id="textBehaviorDesc">
                Current: Users will see a strong warning dialog but can choose to continue sending.
            </p>
        </div>
        
        <!-- Sensitivity Settings -->
        <div class="settings-card">
            <h3 class="settings-title">Detection Sensitivity</h3>
            <div class="sensitivity-levels" id="sensitivityLevels">
                <button class="sensitivity-btn" data-level="1">
                    <div class="level">1</div>
                    <div class="label">Low</div>
                    <div class="desc">Only obvious PHI</div>
                </button>
                <button class="sensitivity-btn" data-level="2">
                    <div class="level">2</div>
                    <div class="label">Medium</div>
                    <div class="desc">Clear violations</div>
                </button>
                <button class="sensitivity-btn active" data-level="3">
                    <div class="level">3</div>
                    <div class="label">Recommended</div>
                    <div class="desc">Balanced detection</div>
                </button>
                <button class="sensitivity-btn" data-level="4">
                    <div class="level">4</div>
                    <div class="label">High</div>
                    <div class="desc">Maximum protection</div>
                </button>
            </div>
        </div>
        
        <!-- Rules Management -->
        <div class="settings-card">
            <h3 class="card-title">📋 HIPAA Rules Management</h3>
            <p class="card-subtitle" style="color: var(--text-muted); margin-bottom: 20px;">
                Backend-updatable detection rules. Extensions fetch these rules periodically.
            </p>
            <div class="rules-info" style="display: flex; gap: 40px; margin-bottom: 20px;">
                <div>
                    <div class="stat-label">Current Version</div>
                    <div class="stat-value" id="rulesVersion" style="font-size: 24px;">-</div>
                </div>
                <div>
                    <div class="stat-label">Last Updated</div>
                    <div class="stat-value" id="rulesLastUpdated" style="font-size: 16px; color: var(--text-muted);">-</div>
                </div>
                <div>
                    <div class="stat-label">Strong Identifiers</div>
                    <div class="stat-value" id="rulesStrongCount" style="font-size: 24px; color: var(--orange);">-</div>
                </div>
                <div>
                    <div class="stat-label">Health Keywords</div>
                    <div class="stat-value" id="rulesHealthCount" style="font-size: 24px; color: var(--green);">-</div>
                </div>
            </div>
            <div style="display: flex; gap: 10px;">
                <button class="sensitivity-btn" id="viewRulesBtn" style="padding: 12px 24px; flex: none; color: var(--text);">
                    👁️ View Current Rules
                </button>
                <button class="sensitivity-btn" id="refreshRulesBtn" style="padding: 12px 24px; flex: none; background: var(--dark-lighter); color: var(--text);">
                    🔄 Force Refresh to Extensions
                </button>
            </div>
            
            <!-- Rules Details (hidden by default) -->
            <div id="rulesDetails" style="display: none; margin-top: 20px; background: var(--dark); border-radius: 8px; padding: 16px; max-height: 400px; overflow-y: auto;">
                <pre id="rulesJson" style="font-family: monospace; font-size: 12px; white-space: pre-wrap;"></pre>
            </div>
        </div>
        
        <!-- Feedback Statistics -->
        <div class="settings-card">
            <h3 class="card-title">📊 Feedback Statistics</h3>
            <p class="card-subtitle" style="color: var(--text-muted); margin-bottom: 20px;">
                User-reported false positives and missed detections for improving accuracy.
            </p>
            <div class="stats-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom: 20px;">
                <div class="stat-card">
                    <div class="stat-label">Total Feedback</div>
                    <div class="stat-value" id="totalFeedback">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">False Positives</div>
                    <div class="stat-value orange" id="falsePositivesCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Missed Detections</div>
                    <div class="stat-value red" id="falseNegativesCount">0</div>
                </div>
            </div>
            
            <!-- Recent Feedback Table -->
            <div class="table-card" style="margin-top: 20px;">
                <div class="table-header">
                    <h3 class="table-title">Recent Feedback</h3>
                    <button class="sensitivity-btn" id="refreshFeedbackBtn" style="padding: 8px 16px; flex: none; color: var(--text);">
                        🔄 Refresh
                    </button>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Detected</th>
                            <th>Expected</th>
                            <th>Platform</th>
                            <th>Time</th>
                            <th>Text Preview</th>
                        </tr>
                    </thead>
                    <tbody id="feedbackTableBody">
                        <tr>
                            <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 20px;">
                                No feedback yet. Click Refresh to load.
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Overrides Table -->
        <div class="table-card">
            <div class="table-header">
                <h3 class="table-title">Override Statistics</h3>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Status Level</th>
                        <th>Override Count</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="badge orange">Orange</span></td>
                        <td id="orangeOverrides">0</td>
                        <td>Users who submitted despite caution warnings</td>
                    </tr>
                    <tr>
                        <td><span class="badge red">Red</span></td>
                        <td id="redOverrides">0</td>
                        <td>Users who submitted despite violation warnings</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </main>
    
    <script>
        // Charts
        let statusChart, titleChart;
        
        // Initialize charts
        function initCharts() {
            const statusCtx = document.getElementById('statusChart').getContext('2d');
            statusChart = new Chart(statusCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Safe', 'Caution', 'Violation'],
                    datasets: [{
                        data: [0, 0, 0],
                        backgroundColor: ['#22c55e', '#f59e0b', '#ef4444'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#94a3b8' }
                        }
                    }
                }
            });
            
            const titleCtx = document.getElementById('titleChart').getContext('2d');
            titleChart = new Chart(titleCtx, {
                type: 'bar',
                data: {
                    labels: ['Title I', 'Title II', 'Title III', 'Title IV', 'Title V'],
                    datasets: [{
                        label: 'Violations',
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: '#3b82f6',
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            ticks: { color: '#94a3b8' }
                        },
                        x: {
                            grid: { display: false },
                            ticks: { color: '#94a3b8' }
                        }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }
        
        // Text message behavior descriptions
        const TEXT_BEHAVIOR_DESCS = {
            'block': 'Current: Messages containing PHI will be automatically blocked from sending.',
            'warn_with_override': 'Current: Users will see a strong warning dialog but can choose to continue sending.',
            'log_only': 'Current: Messages are allowed but PHI detection events are logged for review.'
        };
        
        // Upload behavior descriptions
        const UPLOAD_BEHAVIOR_DESCS = {
            'block': 'Current: Files containing PHI will be automatically blocked from upload.',
            'warn_with_override': 'Current: Users will see a strong warning dialog but can choose to continue uploading.',
            'log_only': 'Current: Uploads are allowed but PHI detection events are logged for review.'
        };
        
        // Fetch and update stats
        async function fetchStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                
                // Update stat cards
                document.getElementById('totalScans').textContent = data.total_scans.toLocaleString();
                document.getElementById('greenPercent').textContent = data.percentages.green + '%';
                document.getElementById('orangePercent').textContent = data.percentages.orange + '%';
                document.getElementById('redPercent').textContent = data.percentages.red + '%';
                
                // Update overrides
                document.getElementById('orangeOverrides').textContent = data.overrides.orange;
                document.getElementById('redOverrides').textContent = data.overrides.red;
                
                // Update file upload stats
                if (data.file_stats) {
                    document.getElementById('fileTotal').textContent = data.file_stats.total.toLocaleString();
                    document.getElementById('fileGreen').textContent = data.file_stats.green.toLocaleString();
                    document.getElementById('fileOrange').textContent = data.file_stats.orange.toLocaleString();
                    document.getElementById('fileRed').textContent = data.file_stats.red.toLocaleString();
                    document.getElementById('fileBlocked').textContent = data.file_stats.blocked.toLocaleString();
                    document.getElementById('fileOverrides').textContent = data.file_stats.overrides.toLocaleString();
                }
                
                // Update text behavior buttons
                const currentTextBehavior = data.text_red_behavior || 'warn_with_override';
                document.querySelectorAll('.text-behavior-btn').forEach(btn => {
                    btn.classList.toggle('active', btn.dataset.behavior === currentTextBehavior);
                });
                document.getElementById('textBehaviorDesc').textContent = TEXT_BEHAVIOR_DESCS[currentTextBehavior];
                
                // Update upload behavior buttons
                const currentBehavior = data.upload_red_behavior || data.pdf_red_behavior || 'warn_with_override';
                document.querySelectorAll('.upload-behavior-btn').forEach(btn => {
                    btn.classList.toggle('active', btn.dataset.behavior === currentBehavior);
                });
                document.getElementById('uploadBehaviorDesc').textContent = UPLOAD_BEHAVIOR_DESCS[currentBehavior];
                
                // Update charts
                statusChart.data.datasets[0].data = [
                    data.counts.green,
                    data.counts.orange,
                    data.counts.red
                ];
                statusChart.update();
                
                titleChart.data.datasets[0].data = [
                    data.by_title['Title I'] || 0,
                    data.by_title['Title II'] || 0,
                    data.by_title['Title III'] || 0,
                    data.by_title['Title IV'] || 0,
                    data.by_title['Title V'] || 0
                ];
                titleChart.update();
                
                // Update sensitivity buttons
                const currentLevel = data.sensitivity_level;
                document.querySelectorAll('.sensitivity-btn:not(.pdf-behavior-btn)').forEach(btn => {
                    if (btn.dataset.level) {
                        btn.classList.toggle('active', parseInt(btn.dataset.level) === currentLevel);
                    }
                });
                
            } catch (error) {
                console.error('Failed to fetch stats:', error);
            }
        }
        
        // Sensitivity button handlers
        document.querySelectorAll('.sensitivity-btn:not(.pdf-behavior-btn)').forEach(btn => {
            if (!btn.dataset.level) return;
            btn.addEventListener('click', async () => {
                const level = parseInt(btn.dataset.level);
                try {
                    await fetch('/api/settings', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ sensitivity_level: level })
                    });
                    
                    document.querySelectorAll('.sensitivity-btn:not(.pdf-behavior-btn)').forEach(b => {
                        if (b.dataset.level) {
                            b.classList.toggle('active', parseInt(b.dataset.level) === level);
                        }
                    });
                } catch (error) {
                    console.error('Failed to update settings:', error);
                }
            });
        });
        
        // Text behavior button handlers
        document.querySelectorAll('.text-behavior-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const behavior = btn.dataset.behavior;
                try {
                    await fetch('/api/settings', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ text_red_behavior: behavior })
                    });
                    
                    document.querySelectorAll('.text-behavior-btn').forEach(b => {
                        b.classList.toggle('active', b.dataset.behavior === behavior);
                    });
                    document.getElementById('textBehaviorDesc').textContent = TEXT_BEHAVIOR_DESCS[behavior];
                } catch (error) {
                    console.error('Failed to update text behavior:', error);
                }
            });
        });
        
        // Upload behavior button handlers
        document.querySelectorAll('.upload-behavior-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const behavior = btn.dataset.behavior;
                try {
                    await fetch('/api/settings', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ upload_red_behavior: behavior })
                    });
                    
                    document.querySelectorAll('.upload-behavior-btn').forEach(b => {
                        b.classList.toggle('active', b.dataset.behavior === behavior);
                    });
                    document.getElementById('uploadBehaviorDesc').textContent = UPLOAD_BEHAVIOR_DESCS[behavior];
                } catch (error) {
                    console.error('Failed to update upload behavior:', error);
                }
            });
        });
        
        // Initialize
        initCharts();
        fetchStats();
        fetchRules();
        
        // Refresh stats every 30 seconds
        setInterval(fetchStats, 30000);
        
        // ========================================
        // RULES MANAGEMENT
        // ========================================
        
        async function fetchRules() {
            try {
                const response = await fetch('/api/rules');
                const data = await response.json();
                
                if (data.status === 'ok') {
                    document.getElementById('rulesVersion').textContent = data.version || 1;
                    document.getElementById('rulesLastUpdated').textContent = 
                        data.last_updated ? new Date(data.last_updated).toLocaleString() : 'Never';
                    document.getElementById('rulesStrongCount').textContent = 
                        Object.keys(data.strong_identifiers || {}).length;
                    document.getElementById('rulesHealthCount').textContent = 
                        Object.keys(data.health_context || {}).length;
                    
                    // Store for display
                    window.currentRules = data;
                }
            } catch (error) {
                console.error('Failed to fetch rules:', error);
            }
        }
        
        // View Rules button
        document.getElementById('viewRulesBtn').addEventListener('click', () => {
            const details = document.getElementById('rulesDetails');
            const isHidden = details.style.display === 'none';
            
            if (isHidden && window.currentRules) {
                document.getElementById('rulesJson').textContent = 
                    JSON.stringify(window.currentRules, null, 2);
            }
            
            details.style.display = isHidden ? 'block' : 'none';
            document.getElementById('viewRulesBtn').textContent = 
                isHidden ? '🙈 Hide Rules' : '👁️ View Current Rules';
        });
        
        // Refresh Rules button (force version increment)
        document.getElementById('refreshRulesBtn').addEventListener('click', async () => {
            const btn = document.getElementById('refreshRulesBtn');
            btn.disabled = true;
            btn.textContent = '⏳ Refreshing...';
            
            try {
                // Just increment version to trigger extension refresh
                const response = await fetch('/api/rules', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({})  // Empty update just increments version
                });
                
                if (response.ok) {
                    await fetchRules();
                    alert('Rules version incremented. Extensions will fetch new rules within the hour.');
                } else {
                    alert('Failed to refresh rules. Make sure you are logged in.');
                }
            } catch (error) {
                console.error('Failed to refresh rules:', error);
                alert('Failed to refresh rules: ' + error.message);
            } finally {
                btn.disabled = false;
                btn.textContent = '🔄 Force Refresh to Extensions';
            }
        });
        
        // Load feedback statistics
        async function loadFeedbackStats() {
            try {
                const response = await fetch('/api/feedback/stats');
                if (!response.ok) throw new Error('Failed to fetch feedback');
                const data = await response.json();
                
                // Update stats
                document.getElementById('totalFeedback').textContent = data.total_feedback.toLocaleString();
                document.getElementById('falsePositivesCount').textContent = data.false_positives_count.toLocaleString();
                document.getElementById('falseNegativesCount').textContent = data.false_negatives_count.toLocaleString();
                
                // Update table
                const tbody = document.getElementById('feedbackTableBody');
                const allFeedback = [
                    ...data.recent_false_positives.map(f => ({...f, type: 'False Positive'})),
                    ...data.recent_false_negatives.map(f => ({...f, type: 'Missed Detection'}))
                ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 20);
                
                if (allFeedback.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 20px;">No feedback received yet.</td></tr>';
                } else {
                    tbody.innerHTML = allFeedback.map(f => {
                        const date = new Date(f.timestamp);
                        const timeStr = date.toLocaleString();
                        const textPreview = f.text.length > 50 ? f.text.substring(0, 50) + '...' : f.text;
                        const typeClass = f.type === 'False Positive' ? 'orange' : 'red';
                        return `
                            <tr>
                                <td><span class="badge ${typeClass}">${f.type}</span></td>
                                <td><span class="badge ${f.detected_status}">${f.detected_status}</span></td>
                                <td><span class="badge ${f.expected_status}">${f.expected_status}</span></td>
                                <td style="font-size: 12px;">${f.platform || 'unknown'}</td>
                                <td style="font-size: 12px; color: var(--text-muted);">${timeStr}</td>
                                <td style="font-size: 11px; color: var(--text-muted); max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${f.text.replace(/"/g, '&quot;')}">${textPreview}</td>
                            </tr>
                        `;
                    }).join('');
                }
            } catch (error) {
                console.error('Failed to load feedback:', error);
                document.getElementById('feedbackTableBody').innerHTML = 
                    '<tr><td colspan="6" style="text-align: center; color: var(--red); padding: 20px;">Error loading feedback data.</td></tr>';
            }
        }
        
        // Refresh feedback button
        document.getElementById('refreshFeedbackBtn').addEventListener('click', () => {
            loadFeedbackStats();
        });
        
        // Load feedback on page load
        loadFeedbackStats();
        
        // Auto-refresh feedback every 30 seconds
        setInterval(loadFeedbackStats, 30000);
    </script>
</body>
</html>
"""

@app.get("/landing", response_class=HTMLResponse)
async def landing_page():
    """Serve the landing page."""
    return LANDING_PAGE_HTML

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Serve the login page."""
    return LOGIN_PAGE_HTML

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    """Serve the admin dashboard (requires authentication)."""
    user = verify_session(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    
    return ADMIN_DASHBOARD_HTML

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

