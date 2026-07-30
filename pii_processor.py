"""
PII Detection and Anonymization for Australian Data

This module provides a class for detecting and anonymizing Personally Identifiable Information (PII)
in text, with a focus on Australian-specific identifiers such as TFN, ABN, Medicare, and various
phone number formats.
"""
import re
import random
from typing import List, Optional, Dict, Any, Callable
from faker import Faker
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, EntityRecognizer, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
import argparse
import sys

class AUPIIProcessor:
    """A class for detecting and anonymizing Australian PII in text."""
    
    def __init__(self, seed: int = 42):
        """Initialize the PII processor with a random seed for reproducibility.
        
        Args:
            seed: Random seed for reproducible results (default: 42)
        """
        self._rng = random.Random(seed)
        self.fake = Faker("en_AU")
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        
        # Remove default PHONE_NUMBER recognizers to avoid conflicts
        self._remove_default_phone_recognizers()
        
        # Register all Australian PII recognizers
        self._register_recognizers()
        
        # Define default operators for anonymization
        self.default_operators = self._get_default_operators()
    
    def _remove_default_phone_recognizers(self) -> None:
        """Remove default phone number recognizers to avoid conflicts with our custom ones."""
        for rec in list(self.analyzer.registry.recognizers):
            if getattr(rec, "supported_entity", None) == "PHONE_NUMBER":
                self.analyzer.registry.remove_recognizer(rec)
    
    def _register_recognizers(self) -> None:
        """Register all custom Australian PII recognizers."""
        # Register AU phone numbers
        self.analyzer.registry.add_recognizer(self.AUMobileNatRecognizer())
        self.analyzer.registry.add_recognizer(self.AUMobileIntRecognizer())
        self.analyzer.registry.add_recognizer(self.AULandNatRecognizer())
        self.analyzer.registry.add_recognizer(self.AULandIntRecognizer())
        self.analyzer.registry.add_recognizer(self.AU13Recognizer())
        self.analyzer.registry.add_recognizer(self.AU1300Recognizer())
        self.analyzer.registry.add_recognizer(self.AU1800Recognizer())
        
        # Register AU IDs
        self.analyzer.registry.add_recognizer(self.TFNRecognizer())
        self.analyzer.registry.add_recognizer(self.ABNRecognizer())
        self.analyzer.registry.add_recognizer(self.MedicareRecognizer(strict_checksum=True))
        self.analyzer.registry.add_recognizer(self.DriverLicenseRecognizer())
    
    def _get_default_operators(self) -> Dict[str, OperatorConfig]:
        """Get the default operators for anonymization."""
        return {
            "DEFAULT":           OperatorConfig("redact", {}),
            "PERSON":            OperatorConfig("replace", {"new_value": "<<PERSON>>"}),
            "EMAIL_ADDRESS":     OperatorConfig("replace", {"new_value": "<<EMAIL>>"}),
            "IP_ADDRESS":        OperatorConfig("replace", {"new_value": "<<IP>>"}),
            
            # Phone numbers
            "AU_MOBILE":         OperatorConfig("replace", {"new_value": "<<AU_MOBILE>>"}),
            "AU_MOBILE_INT":     OperatorConfig("replace", {"new_value": "<<AU_MOBILE_INT>>"}),
            "AU_LANDLINE":       OperatorConfig("replace", {"new_value": "<<AU_LANDLINE>>"}),
            "AU_LANDLINE_INT":   OperatorConfig("replace", {"new_value": "<<AU_LANDLINE_INT>>"}),
            "AU_13":             OperatorConfig("replace", {"new_value": "<<AU_13>>"}),
            "AU_1300":           OperatorConfig("replace", {"new_value": "<<AU_1300>>"}),
            "AU_1800":           OperatorConfig("replace", {"new_value": "<<AU_1800>>"}),
            
            # Australian IDs
            "AU_TFN":            OperatorConfig("replace", {"new_value": "<<TFN_REDACTED>>"}),
            "AU_ABN":            OperatorConfig("replace", {"new_value": "<<ABN_REDACTED>>"}),
            "AU_MEDICARE":       OperatorConfig("replace", {"new_value": "<<MEDICARE_REDACTED>>"}),
            "AU_DRIVER_LICENSE": OperatorConfig("replace", {"new_value": "<<DRIVER_LICENSE_REDACTED>>"}),
        }
    
    def detect_pii(self, text: str, entities: Optional[List[str]] = None, 
                  score_threshold: float = 0.4) -> List[RecognizerResult]:
        """Detect PII entities in the given text.
        
        Args:
            text: The text to analyze for PII
            entities: List of entity types to detect (None for all)
            score_threshold: Confidence threshold (0.0-1.0) for detection
            
        Returns:
            List of detection results
        """
        if entities is None:
            entities = list(self.default_operators.keys())
            
        return self.analyzer.analyze(
            text=text, 
            entities=entities, 
            language="en", 
            score_threshold=score_threshold
        )
    
    def anonymize(self, text: str, results: List[RecognizerResult] = None,
                 custom_operators: Dict[str, OperatorConfig] = None) -> str:
        """Anonymize detected PII in the text.
        
        Args:
            text: The text to anonymize
            results: Pre-computed PII detection results (None to detect automatically)
            custom_operators: Custom operators to use (None to use defaults)
            
        Returns:
            Anonymized text with PII replaced by placeholders
        """
        if results is None:
            results = self.detect_pii(text)
            
        operators = {**self.default_operators, **(custom_operators or {})}
        
        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators
        )
        
        return anonymized.text
    
    def anonymize_with_synthetic(self, text: str) -> str:
        """Anonymize text and replace placeholders with synthetic data.
        
        Args:
            text: The text to process
            
        Returns:
            Text with PII replaced by synthetic data
        """
        anonymized = self.anonymize(text)
        return self._replace_placeholders_with_synthetic(anonymized)
    
    def _replace_placeholders_with_synthetic(self, text: str) -> str:
        """Replace placeholders in the text with synthetic data."""
        replacements = {
            "<<PERSON>>": self.fake.name,
            "<<EMAIL>>": self.fake.email,
            "<<IP>>": self.fake.ipv4_private,
            "<<AU_MOBILE>>": lambda: self.gen_au_mobile(national=True),
            "<<AU_MOBILE_INT>>": lambda: self.gen_au_mobile(national=False),
            "<<AU_LANDLINE>>": lambda: self.gen_au_landline(national=True),
            "<<AU_LANDLINE_INT>>": lambda: self.gen_au_landline(national=False),
            "<<AU_13>>": self.gen_au_13,
            "<<AU_1300>>": self.gen_au_1300,
            "<<AU_1800>>": self.gen_au_1800,
            "<<TFN_REDACTED>>": self.generate_tfn,
            "<<ABN_REDACTED>>": self.generate_abn,
            "<<MEDICARE_REDACTED>>": self.generate_medicare,
            "<<DRIVER_LICENSE_REDACTED>>": lambda: str(self._rng.randint(1000000, 9999999999)),
        }
        
        for placeholder, generator in replacements.items():
            if placeholder in text:
                text = text.replace(placeholder, generator())
                
        return text
    
    # ===== AU PII Recognizers =====
    
    class TFNRecognizer(PatternRecognizer):
        """Recognize Australian Tax File Numbers (TFN)."""
        def __init__(self):
            pat = r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b"
            super().__init__(
                supported_entity="AU_TFN",
                patterns=[Pattern("TFN", pat, 0.7)],
                context=["tfn", "tax file", "tax-file", "tax-file-number", "tax file number"],
            )
        
        def validate_result(self, pattern_text: str) -> bool:
            """Validate a potential TFN using the checksum algorithm."""
            t = re.sub(r"\D", "", pattern_text)
            if not re.fullmatch(r"\d{9}", t):
                return False
            weights = [1, 4, 3, 7, 5, 8, 6, 9, 10]
            return sum(int(d) * w for d, w in zip(t, weights)) % 11 == 0
    
    class ABNRecognizer(PatternRecognizer):
        """Recognize Australian Business Numbers (ABN)."""
        def __init__(self):
            pat = r"\b\d{2}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{3}\b"
            super().__init__(
                supported_entity="AU_ABN",
                patterns=[Pattern("ABN", pat, 0.7)],
                context=["abn", "australian business number", "business number"],
            )
        
        def validate_result(self, pattern_text: str) -> bool:
            """Validate a potential ABN using the checksum algorithm."""
            a = re.sub(r"\D", "", pattern_text)
            if not re.fullmatch(r"\d{11}", a):
                return False
            digits = [int(d) for d in a]
            digits[0] -= 1
            weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
            return sum(d * w for d, w in zip(digits, weights)) % 89 == 0
    
    class MedicareRecognizer(PatternRecognizer):
        """Recognize Australian Medicare numbers."""
        def __init__(self, strict_checksum: bool = True):
            pat = r"\b(?:\d{4}[-\s]?\d{5}[-\s]?\d|\d{10})\b"
            self.strict_checksum = strict_checksum
            super().__init__(
                supported_entity="AU_MEDICARE",
                patterns=[Pattern("Medicare", pat, 0.85)],
                context=["medicare", "medicare no", "medicare number", "medicare card"],
            )
        
        def validate_result(self, pattern_text: str) -> bool:
            """Validate a potential Medicare number using the checksum algorithm."""
            if not self.strict_checksum:
                return True
                
            m = re.sub(r"\D", "", pattern_text)
            if not re.fullmatch(r"\d{10}", m):
                return False
                
            first8 = [int(d) for d in m[:8]]
            issue = int(m[8])
            check = int(m[9])
            
            if issue < 1 or issue > 9:
                return False
                
            weights = [1, 3, 7, 9, 1, 3, 7, 9]
            return (sum(d * w for d, w in zip(first8, weights)) % 10) == check
    
    class DriverLicenseRecognizer(PatternRecognizer):
        """Recognize Australian Driver License numbers."""
        def __init__(self):
            pat = r"\b\d{7,10}\b"
            super().__init__(
                supported_entity="AU_DRIVER_LICENSE",
                patterns=[Pattern("DriverLicence", pat, 0.5)],
                context=["driver licence", "drivers licence", "driver's licence",
                         "licence no", "licence number", "dl no", "nsw licence", 
                         "vic licence", "qld licence"],
            )
    
    # Phone number recognizers
    
    class AUMobileNatRecognizer(PatternRecognizer):
        """Recognize Australian mobile numbers in national format (04xx xxx xxx)."""
        def __init__(self):
            super().__init__(
                supported_entity="AU_MOBILE",
                patterns=[Pattern("AUMobileNat", r"\b04\d{2}[-\s]?\d{3}[-\s]?\d{3}\b", 0.85)],
                context=["mobile", "phone", "tel", "contact", "call"],
            )
    
    class AUMobileIntRecognizer(PatternRecognizer):
        """Recognize Australian mobile numbers in international format (+61 4xx xxx xxx)."""
        def __init__(self):
            super().__init__(
                supported_entity="AU_MOBILE_INT",
                patterns=[Pattern("AUMobileInt", r"\+61\s?4\d{2}[-\s]?\d{3}[-\s]?\d{3}\b", 0.85)],
                context=["mobile", "phone", "tel", "contact", "call"],
            )
    
    class AULandNatRecognizer(PatternRecognizer):
        """Recognize Australian landline numbers in national format (0x xxxx xxxx)."""
        def __init__(self):
            super().__init__(
                supported_entity="AU_LANDLINE",
                patterns=[Pattern("AULandNat", r"\b0[2378]\s?\d{4}\s?\d{4}\b", 0.8)],
                context=["phone", "tel", "landline", "contact", "call"],
            )
    
    class AULandIntRecognizer(PatternRecognizer):
        """Recognize Australian landline numbers in international format (+61 x xxxx xxxx)."""
        def __init__(self):
            super().__init__(
                supported_entity="AU_LANDLINE_INT",
                patterns=[Pattern("AULandInt", r"\+61\s?[2378]\s?\d{4}\s?\d{4}\b", 0.8)],
                context=["phone", "tel", "landline", "contact", "call"],
            )
    
    class AU13Recognizer(PatternRecognizer):
        """Recognize Australian 13/1300/1800 numbers (13 xx xx)."""
        def __init__(self):
            super().__init__(
                supported_entity="AU_13",
                patterns=[Pattern("AU13", r"\b13\s?\d{2}\s?\d{2}\b", 0.75)],
                context=["phone", "tel", "contact", "call"],
            )
    
    class AU1300Recognizer(PatternRecognizer):
        """Recognize Australian 1300 numbers (1300 xxx xxx)."""
        def __init__(self):
            super().__init__(
                supported_entity="AU_1300",
                patterns=[Pattern("AU1300", r"\b1300\s?\d{3}\s?\d{3}\b", 0.75)],
                context=["phone", "tel", "contact", "call"],
            )
    
    class AU1800Recognizer(PatternRecognizer):
        """Recognize Australian 1800 numbers (1800 xxx xxx)."""
        def __init__(self):
            super().__init__(
                supported_entity="AU_1800",
                patterns=[Pattern("AU1800", r"\b1800\s?\d{3}\s?\d{3}\b", 0.75)],
                context=["phone", "tel", "contact", "call"],
            )
    
    # ===== Synthetic Data Generators =====
    
    def generate_tfn(self) -> str:
        """Generate a valid Australian Tax File Number (TFN)."""
        while True:
            # Generate 9 random digits
            digits = [self._rng.randint(0, 9) for _ in range(8)]
            
            # Calculate checksum digit
            weights = [1, 4, 3, 7, 5, 8, 6, 9, 10]
            total = sum(d * w for d, w in zip(digits, weights))
            check_digit = (11 - (total % 11)) % 10
            tfn_digits = digits + [check_digit]
            
            # Format as a string with optional hyphens
            tfn = ''.join(map(str, tfn_digits))
            if len(tfn) == 9:  # Extra validation
                return f"{tfn[:3]}-{tfn[3:6]}-{tfn[6:]}"
    
    def generate_abn(self) -> str:
        """Generate a valid Australian Business Number (ABN)."""
        while True:
            # Generate 11 random digits
            digits = [self._rng.randint(0, 9) for _ in range(11)]
            
            # Calculate checksum
            weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
            total = sum(d * w for d, w in zip(digits, weights))
            
            # Adjust first digit to make the total divisible by 89
            digits[0] = (digits[0] - (total % 89)) % 10
            
            # Format as a string with optional spaces
            abn = ''.join(map(str, digits))
            if len(abn) == 11:  # Extra validation
                return f"{abn[:2]} {abn[2:5]} {abn[5:8]} {abn[8:]}"
    
    def generate_medicare(self) -> str:
        """Generate a valid Australian Medicare number."""
        while True:
            # Generate 10 digits with issue number between 1-9
            digits = [self._rng.randint(0, 9) for _ in range(8)]
            issue = self._rng.randint(1, 9)
            
            # Calculate checksum
            weights = [1, 3, 7, 9, 1, 3, 7, 9]
            total = sum(d * w for d, w in zip(digits, weights))
            check_digit = total % 10
            
            # Format as a string with optional spaces
            medicare = f"{''.join(map(str, digits[:4]))} {''.join(map(str, digits[4:]))} {issue}{check_digit}"
            
            # Extra validation
            if len(medicare.replace(' ', '')) == 10:
                return medicare
    
    def gen_au_mobile(self, national: bool = True) -> str:
        """Generate an Australian mobile phone number.
        
        Args:
            national: If True, format as 04xx xxx xxx; if False, format as +61 4xx xxx xxx
            
        Returns:
            Formatted phone number string
        """
        prefix = "04"
        number = f"{prefix}{self._rng.randint(0, 9)}{self._rng.randint(0, 9)} {self._rng.randint(0, 9)}{self._rng.randint(0, 9)}{self._rng.randint(0, 9)} {self._rng.randint(0, 9)}{self._rng.randint(0, 9)}{self._rng.randint(0, 9)}"
        
        if not national:
            number = f"+61 {number[1:]}"
            
        return number
    
    def gen_au_landline(self, national: bool = True) -> str:
        """Generate an Australian landline phone number.
        
        Args:
            national: If True, format as 0x xxxx xxxx; if False, format as +61 x xxxx xxxx
            
        Returns:
            Formatted phone number string
        """
        # Common area codes for major cities
        area_codes = ["02", "03", "07", "08"]
        area = self._rng.choice(area_codes)
        
        # Generate the rest of the number
        number = f"{area} {self._rng.randint(1000, 9999)} {self._rng.randint(1000, 9999)}"
        
        if not national:
            # Convert to international format: +61 x xxxx xxxx
            number = f"+61 {area[1:]} {number[3:]}"
            
        return number
    
    def gen_au_13(self) -> str:
        """Generate an Australian 13/1300/1800 number (13 xx xx)."""
        return f"13 {self._rng.randint(10, 99)} {self._rng.randint(10, 99)}"
    
    def gen_au_1300(self) -> str:
        """Generate an Australian 1300 number (1300 xxx xxx)."""
        return f"1300 {self._rng.randint(100, 999)} {self._rng.randint(100, 999)}"
    
    def gen_au_1800(self) -> str:
        """Generate an Australian 1800 number (1800 xxx xxx)."""
        return f"1800 {self._rng.randint(100, 999)} {self._rng.randint(100, 999)}"


def main():
    """Command-line interface for the PII processor."""

    
    parser = argparse.ArgumentParser(description="Detect and anonymize PII in text")
    parser.add_argument("input", nargs="?", help="Input text or file (default: read from stdin)")
    parser.add_argument("-f", "--file", action="store_true", help="Treat input as a file path")
    parser.add_argument("-s", "--synthetic", action="store_true", help="Replace placeholders with synthetic data")
    parser.add_argument("-o", "--output", help="Output file (default: print to stdout)")
    
    args = parser.parse_args()
    
    # Read input
    if args.input:
        if args.file:
            try:
                with open(args.input, 'r', encoding='utf-8') as f:
                    text = f.read()
            except Exception as e:
                print(f"Error reading file: {e}", file=sys.stderr)
                return 1
        else:
            text = args.input
    else:
        # Read from stdin if no input provided
        text = sys.stdin.read()
    
    if not text.strip():
        print("No input provided", file=sys.stderr)
        return 1
    
    # Process the text
    processor = AUPIIProcessor()
    
    if args.synthetic:
        result = processor.anonymize_with_synthetic(text)
    else:
        result = processor.anonymize(text)
    
    # Output the result
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(result)
        except Exception as e:
            print(f"Error writing to file: {e}", file=sys.stderr)
            return 1
    else:
        print(result)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
