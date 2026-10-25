import re
from typing import Dict, Any, Tuple, List, Optional
from guardian_swarm.core.exceptions import (
    PIIDetectedReroutingException,
    ExternalAPIBlockedException,
    OutputRedactionAppliedException,
    DataResidencyViolationException,
    FileClassificationDeniedException
)
from guardian_swarm.core.filemind_classifier import FileMindClassifier

CLASSIFICATION_LEVELS = {
    "PUBLIC": 1,
    "INTERNAL": 2,
    "CONFIDENTIAL": 3,
    "RESTRICTED": 4
}

PII_PATTERNS = {
    "EMAIL": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "PHONE": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "ADDRESS": r"\b\d{1,5}\s+[A-Za-z0-9\s.,-]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way)\b",
    "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "DOB": r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b",
    "API_KEY": r"\b(?:sk-[a-zA-Z0-9]{20,}|bearer\s+[a-zA-Z0-9_\-\.]{20,})\b"
}

class PrivacyGate:
    """
    Gate 3: Privacy Gate.
    Scans inbound prompts and outbound responses with strict regex PII patterns.
    Integrates FileMind content-aware file classification for referenced file paths.
    """
    def __init__(self):
        self.filemind = FileMindClassifier()

    def detect_pii(self, text: str) -> Tuple[bool, List[str]]:
        """Detects PII in string content returning (has_pii, list_of_types)."""
        if not text or not isinstance(text, str):
            return False, []

        found_types = []
        for pii_type, pattern in PII_PATTERNS.items():
            if re.search(pattern, text, re.IGNORECASE):
                found_types.append(pii_type)

        return len(found_types) > 0, found_types

    def scan(
        self,
        prompt: str,
        data_classification: str = "INTERNAL",
        pii_action: str = "reroute",
        allowed_regions: Optional[List[str]] = None,
        target_region: str = "us-east-1",
        max_allowed_classification: str = "INTERNAL",
        user_role: str = "EMPLOYEE"
    ) -> Dict[str, Any]:
        """
        Scans prompt and parameters before execution.
        Raises PGE_001, PGE_002, PGE_004, or PGE_005 on violations.
        """
        allowed = allowed_regions or ["us-east-1", "us-west-2", "eu-west-1", "local"]

        # 0. FileMind File Classification Check (if prompt references file path)
        file_path_match = re.search(r"['\"]?([a-zA-Z]:[/\\][\w\-\./\\]+\.[a-zA-Z0-9]+|/[\w\-\./]+\.[a-zA-Z0-9]+)['\"]?", prompt)
        file_info = None
        if file_path_match:
            filepath = file_path_match.group(1)
            file_info = self.filemind.classify_file(filepath)
            file_class = file_info.get("guardian_classification", "RESTRICTED")
            
            req_level = CLASSIFICATION_LEVELS.get(file_class, 4)
            max_level = CLASSIFICATION_LEVELS.get(max_allowed_classification, 2)
            
            if req_level > max_level:
                raise FileClassificationDeniedException(
                    file_path=filepath,
                    classification=file_class,
                    max_allowed=max_allowed_classification,
                    role=user_role,
                    reason=f"File content category '{file_info.get('filemind_category')}' mapped to '{file_class}' exceeds role max allowed level '{max_allowed_classification}'"
                )

        # 1. Data Residency Check
        if target_region not in allowed:
            raise DataResidencyViolationException(
                region=target_region,
                reason=f"Target region '{target_region}' is not in permitted residency regions {allowed}."
            )

        # 2. RESTRICTED Data Classification Check
        if data_classification.upper() == "RESTRICTED":
            raise ExternalAPIBlockedException(
                data_classification=data_classification,
                reason=f"External API calls forbidden for data classification '{data_classification}'."
            )

        # 3. PII Scan & Rerouting
        has_pii, pii_types = self.detect_pii(prompt)
        rerouted = False
        masked_prompt = prompt

        if has_pii:
            action = pii_action.lower()
            if action == "reroute":
                rerouted = True
                raise PIIDetectedReroutingException(
                    pii_types=pii_types,
                    reason=f"PII detected ({', '.join(pii_types)}). Request rerouted to local execution model."
                )
            elif action == "block":
                raise ExternalAPIBlockedException(
                    data_classification=data_classification,
                    reason=f"PII detected ({', '.join(pii_types)}) and policy set to block."
                )
            elif action == "mask":
                masked_prompt = self.redact(prompt)

        return {
            "has_pii": has_pii,
            "pii_types": pii_types,
            "rerouted": rerouted,
            "masked_prompt": masked_prompt
        }

    def redact(self, text: str) -> str:
        """Redacts PII from text replacing matches with [REDACTED_TYPE]."""
        if not text or not isinstance(text, str):
            return text
        redacted = text
        redacted_count = 0
        for pii_type, pattern in PII_PATTERNS.items():
            matches = list(re.finditer(pattern, redacted, flags=re.IGNORECASE))
            if matches:
                redacted_count += len(matches)
                redacted = re.sub(pattern, f"[REDACTED_{pii_type}]", redacted, flags=re.IGNORECASE)

        return redacted

    def sanitize_output(self, response_text: str) -> Tuple[str, bool, int]:
        """Scans and redacts outbound agent response text before returning to user."""
        has_pii, pii_types = self.detect_pii(response_text)
        if not has_pii:
            return response_text, False, 0

        clean_text = self.redact(response_text)
        return clean_text, True, len(pii_types)
