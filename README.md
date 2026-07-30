# PST PII Masking

A Python proof of concept for extracting email from Microsoft Outlook PST files and masking personally identifiable information (PII), with additional recognition for common Australian identifiers and phone-number formats.

The project can:

- read messages and transport headers from a PST archive;
- convert HTML email bodies to plain text;
- detect and mask names, email addresses, IP addresses, Australian phone numbers, TFNs, ABNs, Medicare numbers, and driver licence numbers;
- create synthetic replacements for detected values;
- preserve basic email-thread metadata; and
- export processed messages to batched CSV files.

## Important privacy warning

The PST workflow currently keeps original email addresses, subjects, and bodies in memory. CSV exports include the original subjects and bodies, while the email mapping CSV contains original addresses.

Treat PST files, mapping files, and generated CSVs as sensitive. Review exported data before sharing it. These files are excluded by the supplied `.gitignore`, but they should still be stored and transferred securely.

PII detection is probabilistic. Always validate masking quality before using output outside a controlled environment.

## Project structure

| File | Purpose |
| --- | --- |
| `ReadPSTFile.py` | Main PST reader, message processor, thread metadata extractor, and batched CSV exporter |
| `pii_processor.py` | Reusable Australian PII detection and anonymization module with a command-line interface |
| `email_anonymizer.py` | Stable email-address pseudonymization backed by a CSV mapping |
| `GenerateSyntEmails.py` | Windows/Outlook helper for sending test emails from a CSV file |
| `PII Boiler plate.py` | Earlier standalone prototype and sample recognizer script |
| `read_csv_top100.py` | Small utility for previewing the first 100 rows of a CSV |

## Requirements

- Python 3.10 or later
- A platform supported by `libpff`/`libratom` for PST processing
- Windows with desktop Outlook for `GenerateSyntEmails.py`

Install the Python dependencies in a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

On Windows, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Quick start: mask text

Mask text directly:

```bash
python pii_processor.py "Contact Jane Doe on 0412 345 678"
```

Mask the contents of a file:

```bash
python pii_processor.py --file input.txt --output masked.txt
```

Replace detected values with synthetic data:

```bash
python pii_processor.py --synthetic "Contact Jane Doe on 0412 345 678"
```

## Process a PST file

`ReadPSTFile.py` is currently a proof-of-concept script rather than a complete command-line application. Before running it, update these values in its `__main__` block:

- `pst_path`
- `email_mapping_csv`
- `output_csv`

Then run:

```bash
python ReadPSTFile.py
```

The script lists PST folders, processes messages, and writes numbered CSV batches. Its current default processes all non-calendar messages in batches of 2,000.

## Known limitations

- The PST runner uses hard-coded Windows paths and should be converted to command-line arguments for general use.
- CSV output contains selected original fields as well as masked and synthetic fields.
- Detection can produce false positives or miss PII; recognizers and thresholds require validation against the intended dataset.
- Driver licence formats vary by Australian state and are currently detected using a broad context-aware numeric pattern.
- The prototype and helper scripts overlap with the reusable `pii_processor.py` module and may be consolidated later.

## Authors

- Naveen Muralidharan — naveen.muralidharan@uipath.com

## Contributing

Create a branch for your change, avoid committing any real PST or email data, and include synthetic test cases when changing recognizers.
