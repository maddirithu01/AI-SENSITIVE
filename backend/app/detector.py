import re
from dataclasses import dataclass

COMMON_FIRST_NAMES = {
    'alex', 'amanda', 'angela', 'andrew', 'anna', 'ben', 'brian', 'charlie', 'david', 'diana',
    'emma', 'eric', 'frank', 'grace', 'henry', 'isabella', 'jack', 'james', 'jane', 'john',
    'jordan', 'julie', 'karen', 'kevin', 'laura', 'lisa', 'mary', 'michael', 'natalie', 'olivia',
    'peter', 'rachel', 'robert', 'sarah', 'sam', 'sophia', 'steven', 'thomas', 'victoria', 'william'
}
COMMON_LAST_NAMES = {
    'adams', 'allen', 'baker', 'brown', 'campbell', 'clark', 'davis', 'doe', 'evans', 'foster', 'garcia',
    'hall', 'harris', 'jackson', 'johnson', 'jones', 'lee', 'martin', 'miller', 'moore', 'nelson',
    'perez', 'roberts', 'robinson', 'smith', 'thomas', 'turner', 'walker', 'white', 'wilson', 'young'
}

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
PASSWORD_RE = re.compile(r"(?i)(?:password|passwd|pwd|secret|token)\s*(?:[:=]|is)\s*[^\s,;]+")
ADDRESS_RE = re.compile(r"\b\d{1,5}\s+[A-Za-z0-9.\- ]+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Parkway|Pkwy)\b")
MEDICAL_RE = re.compile(r"(?i)\b(?:diagnosis|medication|prescription|medical record|condition|patient id|allergy)\b")

@dataclass
class EntityMatch:
    label: str
    category: str
    value: str
    replacement: str
    start: int
    end: int
    confidence: float
    severity: str


def _mask_for_category(category: str, mode: str) -> str:
    if mode == 'redact':
        return '[REDACTED]'
    replacements = {
        'email_address': '[EMAIL]',
        'phone_number': '[PHONE]',
        'government_id': '[SSN]',
        'payment_card': '[CARD]',
        'password': '[SECRET]',
        'address': '[ADDRESS]',
        'person_name': '[NAME]',
        'medical_info': '[MEDICAL]'
    }
    return replacements.get(category, '[MASKED]')


def _normalize_entity_list(entities):
    deduped = []
    seen = set()
    for entity in sorted(entities, key=lambda item: (item.start, item.end)):
        key = (entity.start, entity.end, entity.category)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entity)
    return deduped


def _build_redacted_text(text: str, entities, mode: str) -> str:
    pieces = []
    cursor = 0
    for entity in sorted(entities, key=lambda item: item.start):
        if entity.start < cursor:
            continue
        pieces.append(text[cursor:entity.start])
        pieces.append(_mask_for_category(entity.category, mode))
        cursor = entity.end
    pieces.append(text[cursor:])
    return ''.join(pieces)


def _detect_person_names(text: str):
    matches = []
    for match in re.finditer(r"\b(?:Mr|Ms|Mrs|Dr)\.??\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b", text):
        value = match.group(0)
        if value:
            matches.append((match.start(), match.end(), value.strip(), 'person_name'))

    for match in re.finditer(r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b", text):
        candidate = match.group(0)
        parts = candidate.split()
        if len(parts) != 2:
            continue
        first, last = parts[0].lower(), parts[1].lower()
        if first in COMMON_FIRST_NAMES and last in COMMON_LAST_NAMES:
            matches.append((match.start(), match.end(), candidate, 'person_name'))

    for match in re.finditer(r"\b[A-Z][a-z]+\s+Doe\b", text):
        candidate = match.group(0)
        matches.append((match.start(), match.end(), candidate, 'person_name'))
    return matches


def detect_sensitive_data(text: str, mode: str = 'mask') -> dict:
    text = text or ''
    entities = []

    detectors = [
        (EMAIL_RE, 'email_address', 'high', 0.98),
        (PHONE_RE, 'phone_number', 'high', 0.93),
        (SSN_RE, 'government_id', 'high', 0.97),
        (CARD_RE, 'payment_card', 'high', 0.9),
        (PASSWORD_RE, 'password', 'high', 0.96),
        (ADDRESS_RE, 'address', 'medium', 0.86),
        (MEDICAL_RE, 'medical_info', 'medium', 0.8),
    ]

    for pattern, category, severity, confidence in detectors:
        for match in pattern.finditer(text):
            value = match.group(0)
            if not value.strip():
                continue
            entities.append(
                EntityMatch(
                    label=category.replace('_', ' ').title(),
                    category=category,
                    value=value,
                    replacement=_mask_for_category(category, mode),
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    severity=severity
                )
            )

    for start, end, value, category in _detect_person_names(text):
        entities.append(
            EntityMatch(
                label='Person Name',
                category=category,
                value=value,
                replacement=_mask_for_category(category, mode),
                start=start,
                end=end,
                confidence=0.82,
                severity='medium'
            )
        )

    valid_entities = _normalize_entity_list(entities)
    redacted_text = _build_redacted_text(text, valid_entities, mode)

    category_counts = {}
    for entity in valid_entities:
        category_counts[entity.category] = category_counts.get(entity.category, 0) + 1

    if not valid_entities:
        risk_level = 'low'
    else:
        risk_scores = {'low': 1, 'medium': 2, 'high': 3}
        max_severity = max((entity.severity for entity in valid_entities), key=lambda item: risk_scores.get(item, 0))
        risk_level = max_severity

    return {
        'id': f'detection-{len(text)}-{len(valid_entities)}',
        'original_text': text,
        'redacted_text': redacted_text,
        'mode': mode,
        'summary': {
            'total_entities': len(valid_entities),
            'categories': category_counts,
            'risk_level': risk_level,
        },
        'entities': [
            {
                'label': entity.label,
                'category': entity.category,
                'value': entity.value,
                'replacement': entity.replacement,
                'severity': entity.severity,
                'confidence': entity.confidence,
                'start': entity.start,
                'end': entity.end,
            }
            for entity in valid_entities
        ],
    }
