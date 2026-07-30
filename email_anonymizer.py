import csv
import os
from dataclasses import dataclass
from email.utils import getaddresses, formataddr
from typing import Dict, List, Optional

def normalize(email: str) -> str:
    return email.strip().lower()


@dataclass
class EmailAnonymizer:
    mapping_csv: str
    keyword: str = "user"
    width: int = 7   # user0000001

    def __post_init__(self):
        self.orig_to_row: Dict[str, dict] = {}
        self.next_id: int = 1
        self._load_mapping()

    def _load_mapping(self):
        os.makedirs(os.path.dirname(self.mapping_csv) or ".", exist_ok=True)

        if not os.path.exists(self.mapping_csv):
            with open(self.mapping_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["id", "original_email", "anonymized_email"])
            return

        with open(self.mapping_csv, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            max_id = 0
            for row in reader:
                orig = normalize(row["original_email"])
                self.orig_to_row[orig] = row
                max_id = max(max_id, int(row["id"]))
            self.next_id = max_id + 1

    def _append_row(self, row: dict):
        with open(self.mapping_csv, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["id", "original_email", "anonymized_email"]
            )
            writer.writerow(row)

    def _build_anonymized(self, id_: int, domain: str) -> str:
        return f"{self.keyword}{id_:0{self.width}d}@{domain}"

    def anonymize_email(self, email: str, new_rows: Optional[List] = None) -> str:
        if not email or "@" not in email:
            return email

        local, domain = email.split("@", 1)
        norm = normalize(email)

        # Lookup
        if norm in self.orig_to_row:
            return self.orig_to_row[norm]["anonymized_email"]

        # Create new mapping
        id_ = self.next_id
        anon = self._build_anonymized(id_, domain)

        row = {
            "id": id_,
            "original_email": email,
            "anonymized_email": anon
        }

        self.orig_to_row[norm] = row
        self._append_row(row)
        self.next_id += 1

        if new_rows is not None:
            new_rows.append((id_, email, anon))

        return anon

    def anonymize_header(self, header: str, new_rows: Optional[List] = None) -> str:
        if not header:
            return header

        rewritten = []
        for name, addr in getaddresses([header]):
            if addr and "@" in addr:
                anon = self.anonymize_email(addr, new_rows)
                rewritten.append(formataddr((name, anon)))
            else:
                rewritten.append(formataddr((name, addr)))

        return ", ".join(rewritten)

    def anonymize_address_list(self, address_list: str, new_rows: Optional[List] = None) -> str:
        """Anonymize a semicolon-separated list of email addresses.

        Args:
            address_list: Semicolon-separated email addresses (e.g., "a@x.com; b@y.com")
            new_rows: Optional list to append new mappings to

        Returns:
            Semicolon-separated anonymized email addresses
        """
        if not address_list:
            return address_list

        emails = [e.strip() for e in address_list.split(";") if e.strip()]
        anonymized = [self.anonymize_email(email, new_rows) for email in emails]
        return "; ".join(anonymized)
