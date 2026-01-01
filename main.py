"""
Korgaurd Beacon - FastAPI Backend
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
    title="Korgaurd Beacon API",
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
    sensitivity_level: int

class LoginRequest(BaseModel):
    username: str
    password: str

# ============================================================================
# IN-MEMORY DATA STORE (Replace with database in production)
# ============================================================================

class DataStore:
    def __init__(self):
        self.reset()
        
    def reset(self):
        self.sensitivity_level = 3
        self.stats = {
            'total_scans': 0,
            'green_count': 0,
            'orange_count': 0,
            'red_count': 0,
            'violations_by_title': defaultdict(int),
            'violations_by_platform': defaultdict(lambda: {'green': 0, 'orange': 0, 'red': 0}),
            'violations_by_type': defaultdict(int),
            'overrides': {'orange': 0, 'red': 0},
            'submit_times': []  # List of (status, time_seconds)
        }
        self.sessions = {}  # session_token -> {username, expires}
        
    def get_stats_summary(self) -> Dict:
        total = self.stats['total_scans'] or 1  # Avoid division by zero
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
            'sensitivity_level': self.sensitivity_level
        }

store = DataStore()

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
                # Patient named X
                r'(?:patient|client|member)\s+(?:named?|is|:)\s*[A-Z][a-z]+\s+[A-Z][a-z]+',
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
                # Explicit DOB mention
                r'\b(?:DOB|date\s*of\s*birth|born(?:\s*on)?)[:\s]+(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4})\b',
                # Full date with month name
                r'\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b',
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
                r'\b(?:in|from|at|lives?\s*in)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?),?\s+(?:[A-Z]{2}|[A-Za-z]+)\b',
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
        
        # Common words that look like names but aren't
        false_positive_names = {
            'the', 'this', 'that', 'here', 'there', 'what', 'when', 'where', 'which',
            'help', 'please', 'thank', 'thanks', 'hello', 'dear', 'best', 'regards',
            'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
            'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august',
            'september', 'october', 'november', 'december', 'new', 'york', 'los', 'angeles'
        }
        
        for match in matches:
            match_lower = match.lower().strip() if isinstance(match, str) else str(match).lower()
            
            # Skip very short matches
            if len(match_lower) < 2:
                continue
            
            # Skip common false positives for names
            if identifier_type in ['full_name', 'first_name_only']:
                words = match_lower.split()
                if any(w in false_positive_names for w in words):
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

@app.post("/api/scan", response_model=ScanResult)
async def scan_text(request: ScanRequest):
    """
    Scan text for HIPAA Privacy Rule PHI disclosure.
    
    Returns:
        - status: green (safe), orange (caution), red (likely PHI disclosure)
        - violations: list of detected issues (backwards compatible)
        - reasons: structured list of health/identifier findings
        - scores: health_score and identifier_score for transparency
    """
    # Create engine with requested sensitivity
    engine = HIPAARulesEngine(request.sensitivity)
    result = engine.scan(request.text)
    
    # Update statistics
    store.stats['total_scans'] += 1
    store.stats[f"{result['status']}_count"] += 1
    
    if request.platform:
        store.stats['violations_by_platform'][request.platform][result['status']] += 1
    
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
    return {"sensitivity_level": store.sensitivity_level}

@app.post("/api/settings")
async def update_settings(settings: SettingsUpdate):
    """Update settings."""
    store.sensitivity_level = settings.sensitivity_level
    return {"success": True, "sensitivity_level": store.sensitivity_level}

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
    <title>Korgaurd Beacon - AI Input Compliance Scanner</title>
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
                <span class="logo-text">Korgaurd <span>Beacon</span></span>
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
                Korgaurd Beacon scans your AI prompts in real-time for HIPAA-sensitive 
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
        <p>© 2024 Korgaurd Beacon • Beacon Health System • HIPAA Compliance Tool</p>
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
    <title>Admin Login - Korgaurd Beacon</title>
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
                <span class="logo-text">Korgaurd <span>Beacon</span></span>
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
    <title>Admin Dashboard - Korgaurd Beacon</title>
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
            <span class="logo-text">Korgaurd <span>Beacon</span></span>
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
                document.querySelectorAll('.sensitivity-btn').forEach(btn => {
                    btn.classList.toggle('active', parseInt(btn.dataset.level) === currentLevel);
                });
                
            } catch (error) {
                console.error('Failed to fetch stats:', error);
            }
        }
        
        // Sensitivity button handlers
        document.querySelectorAll('.sensitivity-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const level = parseInt(btn.dataset.level);
                try {
                    await fetch('/api/settings', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ sensitivity_level: level })
                    });
                    
                    document.querySelectorAll('.sensitivity-btn').forEach(b => {
                        b.classList.toggle('active', parseInt(b.dataset.level) === level);
                    });
                } catch (error) {
                    console.error('Failed to update settings:', error);
                }
            });
        });
        
        // Initialize
        initCharts();
        fetchStats();
        
        // Refresh stats every 30 seconds
        setInterval(fetchStats, 30000);
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

