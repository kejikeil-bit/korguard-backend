# backend/medical_evaluator.py

import re
from dataclasses import dataclass
from typing import List, Dict, Tuple

WORD_SPLIT_RE = re.compile(r"\w+|\S")

# Simple regexes for identifiers
DOB_RE = re.compile(r"\b(0?[1-9]|1[0-2])[/-](0?[1-9]|[12][0-9]|3[01])[/-](\d{2}|\d{4})\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
MRN_RE = re.compile(r"\b\d{6,10}\b")
INSURANCE_ID_RE = re.compile(r"\b[A-Z]{1,3}-\d{6,12}\b", re.IGNORECASE)

# Phrases that often introduce names
NAME_INTRO_PHRASES = [
    "patient name is",
    "patient’s name is",
    "patient's name is",
    "the patient’s name is",
    "the patient's name is",
    "name is",
]

# Very small demo lists – you can expand or move to config.json
MEDICAL_TERMS = [
    "diabetes",
    "hypertension",
    "asthma",
    "pneumonia",
    "carcinoma",
    "cancer",
    "heart attack",
    "myocardial infarction",
    "elevated cholesterol",
    "abnormal liver enzymes",
    "troponin",
    "inhaler",
    "biopsy",
    "lab results",
]

HOSPITAL_TERMS = [
    "hospital",
    "clinic",
    "medical center",
    "cityview hospital",
]


@dataclass
class EvalResult:
    severity: str
    matched_categories: List[str]
    matched_keywords: List[str]
    counts: Dict[str, int]
    explanations: List[str]


class MedicalEvaluator:
    def __init__(self, proximity_window: int = 15):
        self.proximity_window = proximity_window

    def evaluate_text(self, text: str, sensitivity_level: int = 50) -> EvalResult:
        """
        Main entry point: returns severity + details based on PHI + medical proximity.
        This is what main.py calls.
        """

        lowered = text.lower()

        # 1. Detect identifier-like patterns
        identifiers, id_keywords = self._detect_identifiers(lowered)

        # 2. Detect medical / hospital terms
        med_mentions, med_keywords = self._detect_medical_terms(lowered)

        # 3. Decide severity based on presence + proximity
        severity, reasons = self._decide_severity(
            text,
            identifiers,
            med_mentions,
            id_keywords,
            med_keywords,
            sensitivity_level,
        )

        matched_categories = []
        if identifiers:
            matched_categories.append("PHI-Identifier")
        if med_mentions:
            matched_categories.append("Medical-Condition")

        matched_keywords = list(set(id_keywords + med_keywords))

        high_count = len(identifiers)
        medium_count = len(med_mentions)

        return EvalResult(
            severity=severity,
            matched_categories=matched_categories,
            matched_keywords=matched_keywords,
            counts={"high": high_count, "medium": medium_count},
            explanations=reasons,
        )

    # ---------- helpers ----------

    def _detect_identifiers(self, lowered: str) -> Tuple[List[Tuple[int, int]], List[str]]:
        """
        Returns:
          - list of (start_index, end_index) in character space for identifiers
          - list of human-readable identifier keywords
        """
        identifiers = []
        keywords = []

        # Regex-based identifiers
        for regex, label in [
            (DOB_RE, "DOB"),
            (SSN_RE, "SSN"),
            (MRN_RE, "MRN"),
            (INSURANCE_ID_RE, "InsuranceID"),
        ]:
            for m in regex.finditer(lowered):
                identifiers.append((m.start(), m.end()))
                keywords.append(label)

        # Name-intro phrases (very naive)
        for phrase in NAME_INTRO_PHRASES:
            idx = lowered.find(phrase)
            if idx != -1:
                # Mark the phrase range as an identifier anchor
                identifiers.append((idx, idx + len(phrase)))
                keywords.append("NamePhrase")

        return identifiers, keywords

    def _detect_medical_terms(self, lowered: str) -> Tuple[List[Tuple[int, int]], List[str]]:
        mentions = []
        keywords = []

        for term in MEDICAL_TERMS + HOSPITAL_TERMS:
            start = 0
            while True:
                idx = lowered.find(term, start)
                if idx == -1:
                    break
                mentions.append((idx, idx + len(term)))
                keywords.append(term)
                start = idx + len(term)

        return mentions, keywords

    def _decide_severity(
        self,
        text: str,
        identifiers: List[Tuple[int, int]],
        med_mentions: List[Tuple[int, int]],
        id_keywords: List[str],
        med_keywords: List[str],
        sensitivity_level: int,
    ):
        """
        Use proximity between identifiers and medical terms to decide
        green / orange / red.
        """
        reasons: List[str] = []

        # No medical + no identifiers => likely generic / green
        if not identifiers and not med_mentions:
            reasons.append("No medical terms or identifiers detected; treating as generic medical/HIPAA info.")
            return "green", reasons

        # Medical but no identifiers => orange (de-identified clinical)
        if med_mentions and not identifiers:
            reasons.append("Medical content detected without explicit identifiers; treating as de-identified clinical text.")
            return "orange", reasons

        # Identifiers but no medical => borderline; lean orange unless sensitivity very high
        if identifiers and not med_mentions:
            reasons.append("Identifiers detected but no clear medical context; borderline sensitive.")
            if sensitivity_level >= 70:
                reasons.append("Sensitivity level is high; upgrading to red.")
                return "red", reasons
            return "orange", reasons

        # Both identifiers and medical context: check proximity
        if self._identifiers_close_to_medical(text, identifiers, med_mentions):
            reasons.append(
                f"Identifiers appear within {self.proximity_window} words of medical/hospital terms; classifying as PHI."
            )
            return "red", reasons

        # Both present but far apart: call it orange (cautious)
        reasons.append(
            "Both identifiers and medical terms detected but not in close proximity; treating as de-identified with caution."
        )
        return "orange", reasons

    def _identifiers_close_to_medical(
        self,
        text: str,
        identifiers: List[Tuple[int, int]],
        med_mentions: List[Tuple[int, int]],
    ) -> bool:
        """
        Convert character spans into word indices and check if any identifier and
        medical mention are within `self.proximity_window` words of each other.
        """

        tokens = list(WORD_SPLIT_RE.finditer(text))
        if not tokens:
            return False

        # Build mapping from character index to token index
        char_to_token_index = {}
        for i, token in enumerate(tokens):
            for pos in range(token.start(), token.end()):
                char_to_token_index[pos] = i

        def span_to_token_index(span: Tuple[int, int]) -> int:
            start_char = span[0]
            # Find the nearest token index at or after this char
            for offset in range(0, 10):
                if (start_char + offset) in char_to_token_index:
                    return char_to_token_index[start_char + offset]
            return 0

        id_token_indices = [span_to_token_index(span) for span in identifiers]
        med_token_indices = [span_to_token_index(span) for span in med_mentions]

        for id_idx in id_token_indices:
            for med_idx in med_token_indices:
                if abs(id_idx - med_idx) <= self.proximity_window:
                    return True

        return False


