# test_presidio_spacy.py
# -*- coding: utf-8 -*-

import re
import random
import spacy
from faker import Faker

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# --------------------------------------------------------------------
# Env check
# --------------------------------------------------------------------
print("▶ spaCy version:", spacy.__version__)
try:
    nlp = spacy.load("en_core_web_sm")
    doc = nlp("This is a spaCy test. My name is John Doe.")
    print("spaCy pipeline OK. Tokens:", [t.text for t in doc])
except Exception as e:
    print("spaCy load failed:", e)

_rng = random.Random(42)
fake = Faker("en_AU")

def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)

# --------------------------------------------------------------------
# AU Recognizers: TFN / ABN / Medicare / Driver Licence
# --------------------------------------------------------------------
def validate_tfn(text: str) -> bool:
    t = _digits(text)
    if not re.fullmatch(r"\d{9}", t):
        return False
    weights = [1, 4, 3, 7, 5, 8, 6, 9, 10]
    return sum(int(d) * w for d, w in zip(t, weights)) % 11 == 0

class TFNRecognizer(PatternRecognizer):
    def __init__(self):
        pat = r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b"
        super().__init__(
            supported_entity="AU_TFN",
            patterns=[Pattern("TFN", pat, 0.7)],
            context=["tfn", "tax file", "tax-file", "tax-file-number", "tax file number"],
        )
    def validate_result(self, pattern_text: str) -> bool:
        return validate_tfn(pattern_text)

def validate_abn(text: str) -> bool:
    a = _digits(text)
    if not re.fullmatch(r"\d{11}", a):
        return False
    digits = [int(d) for d in a]
    digits[0] -= 1
    weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
    return sum(d * w for d, w in zip(digits, weights)) % 89 == 0

class ABNRecognizer(PatternRecognizer):
    def __init__(self):
        pat = r"\b\d{2}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{3}\b"
        super().__init__(
            supported_entity="AU_ABN",
            patterns=[Pattern("ABN", pat, 0.7)],
            context=["abn", "australian business number", "business number"],
        )
    def validate_result(self, pattern_text: str) -> bool:
        return validate_abn(pattern_text)

def validate_medicare(text: str) -> bool:
    m = _digits(text)
    if not re.fullmatch(r"\d{10}", m):
        return False
    first8 = [int(d) for d in m[:8]]
    issue = int(m[8])
    check = int(m[9])
    if issue < 1 or issue > 9:
        return False
    weights = [1, 3, 7, 9, 1, 3, 7, 9]
    return (sum(d * w for d, w in zip(first8, weights)) % 10) == check

class MedicareRecognizer(PatternRecognizer):
    def __init__(self, strict_checksum: bool = True):
        pat = r"\b(?:\d{4}[-\s]?\d{5}[-\s]?\d|\d{10})\b"
        self.strict_checksum = strict_checksum
        super().__init__(
            supported_entity="AU_MEDICARE",
            patterns=[Pattern("Medicare", pat, 0.85)],  # > phone score
            context=["medicare", "medicare no", "medicare number", "medicare card"],
        )
    def validate_result(self, pattern_text: str) -> bool:
        return validate_medicare(pattern_text) if self.strict_checksum else True

class DriverLicenseRecognizer(PatternRecognizer):
    def __init__(self):
        pat = r"\b\d{7,10}\b"
        super().__init__(
            supported_entity="AU_DRIVER_LICENSE",
            patterns=[Pattern("DriverLicence", pat, 0.5)],
            context=["driver licence","drivers licence","driver's licence",
                     "licence no","licence number","dl no","nsw licence","vic licence","qld licence"],
        )

# --------------------------------------------------------------------
# AU Phone Recognizers as separate entities (so placeholders are specific)
# --------------------------------------------------------------------
class AUMobileNatRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="AU_MOBILE",
            patterns=[Pattern("AUMobileNat", r"\b04\d{2}[-\s]?\d{3}[-\s]?\d{3}\b", 0.85)],
            context=["mobile","phone","tel","contact","call"],
        )

class AUMobileIntRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="AU_MOBILE_INT",
            patterns=[Pattern("AUMobileInt", r"\+61\s?4\d{2}[-\s]?\d{3}[-\s]?\d{3}\b", 0.85)],
            context=["mobile","phone","tel","contact","call"],
        )

class AULandNatRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="AU_LANDLINE",
            patterns=[Pattern("AULandNat", r"\b0[2378]\s?\d{4}\s?\d{4}\b", 0.8)],
            context=["phone","tel","landline","contact","call"],
        )

class AULandIntRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="AU_LANDLINE_INT",
            patterns=[Pattern("AULandInt", r"\+61\s?[2378]\s?\d{4}\s?\d{4}\b", 0.8)],
            context=["phone","tel","landline","contact","call"],
        )

class AU13Recognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="AU_13",
            patterns=[Pattern("AU13", r"\b13\s?\d{2}\s?\d{2}\b", 0.75)],
            context=["phone","tel","contact","call"],
        )

class AU1300Recognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="AU_1300",
            patterns=[Pattern("AU1300", r"\b1300\s?\d{3}\s?\d{3}\b", 0.75)],
            context=["phone","tel","contact","call"],
        )

class AU1800Recognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="AU_1800",
            patterns=[Pattern("AU1800", r"\b1800\s?\d{3}\s?\d{3}\b", 0.75)],
            context=["phone","tel","contact","call"],
        )

# --------------------------------------------------------------------
# Synthetic generators (valid formats)
# --------------------------------------------------------------------
def generate_tfn() -> str:
    weights = [1,4,3,7,5,8,6,9,10]
    while True:
        first8 = [_rng.randint(0,9) for _ in range(8)]
        partial = sum(d*w for d, w in zip(first8, weights[:8]))
        for last in range(10):
            if (partial + last*weights[8]) % 11 == 0:
                d = first8 + [last]
                return f"{d[0]}{d[1]}{d[2]} {d[3]}{d[4]}{d[5]} {d[6]}{d[7]}{d[8]}"

def generate_abn() -> str:
    weights = [10,1,3,5,7,9,11,13,15,17,19]
    while True:
        digits = [_rng.randint(0,9) for _ in range(11)]
        if digits[0] == 0:
            digits[0] = 1
        d0m1 = digits[0] - 1
        total = d0m1*weights[0] + sum(d*w for d, w in zip(digits[1:], weights[1:]))
        if total % 89 == 0:
            return f"{digits[0]}{digits[1]} {digits[2]}{digits[3]}{digits[4]} {digits[5]}{digits[6]}{digits[7]} {digits[8]}{digits[9]}{digits[10]}"

def generate_medicare() -> str:
    weights = [1,3,7,9,1,3,7,9]
    first8 = [_rng.randint(0,9) for _ in range(8)]
    issue = _rng.randint(1,9)
    check = sum(d*w for d, w in zip(first8, weights)) % 10
    return f"{first8[0]}{first8[1]}{first8[2]}{first8[3]} {first8[4]}{first8[5]}{first8[6]}{first8[7]}{issue} {check}"

def gen_au_mobile(national=True):
    d8 = "".join(str(_rng.randint(0, 9)) for _ in range(8))
    if national:
        return f"04{d8[:2]} {d8[2:5]} {d8[5:]}"
    else:
        return f"+61 4{d8[:2]} {d8[2:5]} {d8[5:]}"

def gen_au_landline(national=True):
    area = _rng.choice(["02", "03", "07", "08"])
    local8 = "".join(str(_rng.randint(0, 9)) for _ in range(8))
    if national:
        return f"{area} {local8[:4]} {local8[4:]}"
    else:
        return f"+61 {area[1]} {local8[:4]} {local8[4:]}"

def gen_au_13():   return f"13 {_rng.randint(10,99)} {_rng.randint(10,99)}"
def gen_au_1300(): return f"1300 {_rng.randint(100,999)} {_rng.randint(100,999)}"
def gen_au_1800(): return f"1800 {_rng.randint(100,999)} {_rng.randint(100,999)}"

def replace_placeholders_with_synthetic(text: str) -> str:
    mapping = {
        '<<PERSON>>':               lambda: fake.name(),
        '<<EMAIL>>':                lambda: f"{re.sub(r'[^a-z]', '', fake.name().lower())}.{_rng.randint(100,999)}@example.com",
        '<<IP>>':                   lambda: fake.ipv4_private(),

        '<<AU_MOBILE>>':            lambda: gen_au_mobile(True),
        '<<AU_MOBILE_INT>>':        lambda: gen_au_mobile(False),
        '<<AU_LANDLINE>>':          lambda: gen_au_landline(True),
        '<<AU_LANDLINE_INT>>':      lambda: gen_au_landline(False),
        '<<AU_13>>':                gen_au_13,
        '<<AU_1300>>':              gen_au_1300,
        '<<AU_1800>>':              gen_au_1800,

        '<<TFN_REDACTED>>':         generate_tfn,
        '<<ABN_REDACTED>>':         generate_abn,
        '<<MEDICARE_REDACTED>>':    generate_medicare,
        '<<DRIVER_LICENSE_REDACTED>>': lambda: "".join(str(_rng.randint(0,9)) for _ in range(9)),
    }
    for token, maker in mapping.items():
        if token in text:
            text = text.replace(token, maker())
    return text

# --------------------------------------------------------------------
# Build engines & register recognizers
# --------------------------------------------------------------------
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Remove default PHONE_NUMBER recognizers to avoid conflicts
for rec in list(analyzer.registry.recognizers):
    if getattr(rec, "supported_entity", None) == "PHONE_NUMBER":
        analyzer.registry.remove_recognizer(rec)

# Register AU phones (as separate entities)
analyzer.registry.add_recognizer(AUMobileNatRecognizer())
analyzer.registry.add_recognizer(AUMobileIntRecognizer())
analyzer.registry.add_recognizer(AULandNatRecognizer())
analyzer.registry.add_recognizer(AULandIntRecognizer())
analyzer.registry.add_recognizer(AU13Recognizer())
analyzer.registry.add_recognizer(AU1300Recognizer())
analyzer.registry.add_recognizer(AU1800Recognizer())

# Register AU IDs
analyzer.registry.add_recognizer(TFNRecognizer())
analyzer.registry.add_recognizer(ABNRecognizer())
analyzer.registry.add_recognizer(MedicareRecognizer(strict_checksum=True))
analyzer.registry.add_recognizer(DriverLicenseRecognizer())

# --------------------------------------------------------------------
# Test texts
# --------------------------------------------------------------------
text1 = "My name is John Doe, phone 0400 123 456, and my TFN is 123-456-789."
text2 = """Here are some AU examples:
- Valid TFN: 123 456 782
- ABN: 51 824 753 556
- Medicare: 2951 74989 1
- NSW Licence No: 123456789
- Mobile: +61 412 345 678
- Landline: 02 9876 5432
- 1300: 1300 555 123
- 1800: 1800 123 456
- 13: 13 20 32
- Email: john.doe@example.com
- IP: 192.168.1.10
"""

entities_to_find = [
    "PERSON",
    "EMAIL_ADDRESS",
    "IP_ADDRESS",
    "AU_MOBILE",
    "AU_MOBILE_INT",
    "AU_LANDLINE",
    "AU_LANDLINE_INT",
    "AU_13",
    "AU_1300",
    "AU_1800",
    "AU_TFN",
    "AU_ABN",
    "AU_MEDICARE",
    "AU_DRIVER_LICENSE",
]

for label, txt in [("Sample A (mixed, invalid TFN)", text1), ("Sample B (AU examples)", text2)]:
    print("\n" + "=" * 72)
    print(label)
    print("=" * 72)

    results = analyzer.analyze(text=txt, entities=entities_to_find, language="en", score_threshold=0.4)

    print("\nPresidio detections:")
    if not results:
        print(" - (none)")
    else:
        for r in results:
            snippet = txt[r.start:r.end]
            print(f" - {r.entity_type:16s} ({r.start:>4}-{r.end:<4}): {snippet!r}  Score: {r.score:.2f}")

    operators = {
        "DEFAULT":           OperatorConfig("redact", {}),
        "PERSON":            OperatorConfig("replace", {"new_value": "<<PERSON>>"}),
        "EMAIL_ADDRESS":     OperatorConfig("replace", {"new_value": "<<EMAIL>>"}),
        "IP_ADDRESS":        OperatorConfig("replace", {"new_value": "<<IP>>"}),

        "AU_MOBILE":         OperatorConfig("replace", {"new_value": "<<AU_MOBILE>>"}),
        "AU_MOBILE_INT":     OperatorConfig("replace", {"new_value": "<<AU_MOBILE_INT>>"}),
        "AU_LANDLINE":       OperatorConfig("replace", {"new_value": "<<AU_LANDLINE>>"}),
        "AU_LANDLINE_INT":   OperatorConfig("replace", {"new_value": "<<AU_LANDLINE_INT>>"}),
        "AU_13":             OperatorConfig("replace", {"new_value": "<<AU_13>>"}),
        "AU_1300":           OperatorConfig("replace", {"new_value": "<<AU_1300>>"}),
        "AU_1800":           OperatorConfig("replace", {"new_value": "<<AU_1800>>"}),

        "AU_TFN":            OperatorConfig("replace", {"new_value": "<<TFN_REDACTED>>"}),
        "AU_ABN":            OperatorConfig("replace", {"new_value": "<<ABN_REDACTED>>"}),
        "AU_MEDICARE":       OperatorConfig("replace", {"new_value": "<<MEDICARE_REDACTED>>"}),
        "AU_DRIVER_LICENSE": OperatorConfig("replace", {"new_value": "<<DRIVER_LICENSE_REDACTED>>"}),
    }

    anonymized = anonymizer.anonymize(text=txt, analyzer_results=results, operators=operators)
    print("\nAnonymized text:\n" + anonymized.text)

    synthetic_text = replace_placeholders_with_synthetic(anonymized.text)
    print("\nWith synthetic data:\n" + synthetic_text)

print("\nDone.")
