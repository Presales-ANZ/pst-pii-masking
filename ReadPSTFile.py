from libratom.lib.pff import PffArchive
from typing import Optional, List, Dict
from pii_processor import AUPIIProcessor
from email_anonymizer import EmailAnonymizer
import re
from inscriptis import get_text
from inscriptis.model.config import ParserConfig
from datetime import datetime
import csv
import os
from email import policy
from email.parser import Parser
from email.utils import getaddresses

class PSTReader:
    def __init__(self, email_mapping_csv: str = None):
        self.pii_processor = AUPIIProcessor()
        # Initialize email anonymizer with mapping file
        if email_mapping_csv is None:
            email_mapping_csv = os.path.join(os.path.dirname(__file__) or ".", "email_mapping.csv")
        self.email_anonymizer = EmailAnonymizer(mapping_csv=email_mapping_csv)

    def _extract_threading_info(self, message) -> dict:
        """Extract threading information (Message-ID, Thread-ID, Parent-ID, References) from transport headers."""
        result = {
            "message_id": None,
            "thread_id": None,
            "parent_id": None,
            "references": [],
            "reply_depth": 0,
        }

        try:
            # Get transport headers
            raw_headers = None
            if hasattr(message, 'transport_headers') and message.transport_headers:
                header_content = message.transport_headers
                if isinstance(header_content, bytes):
                    raw_headers = header_content.decode('utf-8', errors='ignore')
                else:
                    raw_headers = str(header_content) if header_content else None

            if not raw_headers:
                return result

            # Parse headers safely (handles folding)
            msg = Parser(policy=policy.default).parsestr(raw_headers)

            message_id = msg.get('Message-ID')
            in_reply_to = msg.get('In-Reply-To')

            # Extract References as a list
            references = []
            if msg.get('References'):
                references = re.findall(r'<[^>]+>', msg.get('References'))

            # --- Thread-ID logic (Reference method) ---
            if references:
                thread_id = references[0]
            elif in_reply_to:
                thread_id = in_reply_to
            else:
                thread_id = message_id

            # --- Parent-ID logic ---
            if in_reply_to:
                parent_id = in_reply_to
            elif references:
                parent_id = references[-1]
            else:
                parent_id = None

            result = {
                "message_id": message_id,
                "thread_id": thread_id,
                "parent_id": parent_id,
                "references": references,
                "reply_depth": len(references),
            }

        except Exception as e:
            print(f"[Warning] Error extracting threading info from headers: {str(e)}")

        return result

    def _extract_addresses_from_headers(self, message) -> dict:
        """Extract From, To, and CC addresses from transport headers."""
        result = {"from": [], "to": [], "cc": []}

        try:
            # Get transport headers
            raw_headers = None
            if hasattr(message, 'transport_headers') and message.transport_headers:
                header_content = message.transport_headers
                if isinstance(header_content, bytes):
                    raw_headers = header_content.decode('utf-8', errors='ignore')
                else:
                    raw_headers = str(header_content) if header_content else None

            if not raw_headers:
                return result

            # Parse headers using RFC-compliant parser
            msg = Parser(policy=policy.default).parsestr(raw_headers)

            from_addr = msg.get('From')
            to_addrs = msg.get_all('To', [])
            cc_addrs = msg.get_all('Cc', [])

            # Parse addresses into (name, email) tuples
            if from_addr:
                result["from"] = getaddresses([from_addr])
            if to_addrs:
                result["to"] = getaddresses(to_addrs)
            if cc_addrs:
                result["cc"] = getaddresses(cc_addrs)

        except Exception as e:
            print(f"[Warning] Error extracting addresses from headers: {str(e)}")

        return result

    def _format_address_list(self, addresses: list) -> str:
        """Format a list of (name, email) tuples into a string of email addresses only."""
        if not addresses:
            return ""
        emails = [email for _, email in addresses if email]
        return "; ".join(emails)

    # Translation table for invisible character cleanup (created once, reused)
    _INVISIBLE_CHAR_TABLE = str.maketrans(
        '\u00A0\u202F\u2007\u2009',  # Replace with spaces
        '    ',
        '\u200B\u200C\u200D\uFEFF\u2060\u034F\u180E\u00AD\u202A\u202B\u202C\u202D\u202E'  # Remove
    )

    def _clean_html_body(self, html_text) -> str:
        """Clean HTML tags and format text properly using inscriptis."""
        if not html_text:
            return ""

        # Convert bytes to string if needed
        if isinstance(html_text, bytes):
            try:
                text = html_text.decode('utf-8', errors='ignore')
            except Exception:
                try:
                    text = html_text.decode('latin-1', errors='ignore')
                except Exception:
                    return ""
        else:
            text = str(html_text)

        # Use inscriptis for HTML-to-text conversion
        config = ParserConfig(display_links=False, display_images=False)
        text = get_text(text, config)

        # Remove invisible Unicode characters (zero-width, directional marks, etc.)
        text = text.translate(self._INVISIBLE_CHAR_TABLE)

        # Clean up whitespace
        # Replace multiple newlines with max 2 newlines
        text = re.sub(r'\n\s*\n\s*\n+', '\n\n', text)
        # Remove leading/trailing whitespace from each line
        text = '\n'.join(line.strip() for line in text.split('\n'))
        # Remove leading/trailing whitespace from entire text
        text = text.strip()

        return text

    def _find_folder_by_path(self, archive, folder_path: str):
        """Find a folder by its path."""
        folder_parts = folder_path.strip("/").split("/")
        
        for folder in archive.folders():
            folder_name_parts = folder.name.split("\\")
            if all(part.lower() in [fp.lower() for fp in folder_name_parts] 
                   for part in folder_parts):
                return folder
        return None

    def _is_calendar_message(self, message) -> bool:
        """Check if a message is a calendar item (appointment, meeting request, etc.)."""
        try:
            message_class = None
            if hasattr(message, 'message_class') and message.message_class:
                message_class = message.message_class
            elif hasattr(message, 'get_message_class'):
                message_class = message.get_message_class()

            if message_class:
                # Calendar-related message classes
                calendar_classes = [
                    'IPM.Appointment',
                    'IPM.Schedule.Meeting',
                    'IPM.Task',
                    'IPM.Activity',
                ]
                message_class_upper = message_class.upper()
                for cal_class in calendar_classes:
                    if message_class_upper.startswith(cal_class.upper()):
                        return True
        except Exception:
            pass
        return False

    def _debug_message_properties(self, message):
        """Debug helper to print all available properties of a message."""
        print("\n=== Message Properties ===")
        for attr in dir(message):
            if not attr.startswith('_'):
                try:
                    value = getattr(message, attr)
                    if not callable(value):
                        print(f"{attr}: {type(value).__name__} = {str(value)[:100]}")
                except Exception as e:
                    print(f"{attr}: [Error: {str(e)}]")
        print("=========================\n")

    def _process_message(self, message) -> dict:
        """Process a single email message and mask PII."""
        # Try multiple methods to get email body
        email_body = ""
        try:
            # Try plain_text_body first (best option)
            if hasattr(message, 'plain_text_body') and message.plain_text_body:
                body_content = message.plain_text_body
                # Convert bytes to string if needed
                if isinstance(body_content, bytes):
                    email_body = body_content.decode('utf-8', errors='ignore')
                else:
                    email_body = str(body_content) if body_content else ""

            # Try body attribute
            elif hasattr(message, 'body') and message.body:
                body_content = message.body
                # Convert bytes to string if needed
                if isinstance(body_content, bytes):
                    email_body = body_content.decode('utf-8', errors='ignore')
                else:
                    email_body = str(body_content) if body_content else ""

            # Try html_body and clean HTML tags
            elif hasattr(message, 'html_body') and message.html_body:
                email_body = self._clean_html_body(message.html_body)

            # Try transport_message_headers
            elif hasattr(message, 'transport_message_headers') and message.transport_message_headers:
                header_content = message.transport_message_headers
                # Convert bytes to string if needed
                if isinstance(header_content, bytes):
                    email_body = header_content.decode('utf-8', errors='ignore')
                else:
                    email_body = str(header_content) if header_content else ""

            # If we got HTML-like content even from plain_text_body, clean it
            if email_body and ('<html' in email_body.lower() or '<body' in email_body.lower() or '<div' in email_body.lower()):
                email_body = self._clean_html_body(email_body)

        except Exception as e:
            email_body = f"[Error extracting body: {str(e)}]"

        # Truncate email body to max 65535 characters
        if email_body and len(email_body) > 65535:
            email_body = email_body[:65535]

        # Get subject
        subject = message.subject or ""

        # Detect PII in both subject and body
        combined_content = f"{subject} {email_body}"
        pii_detections = self.pii_processor.detect_pii(combined_content)

        # Extract PII entity types and count
        pii_entities = {}
        for detection in pii_detections:
            entity_type = detection.entity_type
            if entity_type not in pii_entities:
                pii_entities[entity_type] = 0
            pii_entities[entity_type] += 1

        # Format PII entities as string
        pii_entities_str = ", ".join([f"{entity}: {count}" for entity, count in pii_entities.items()]) if pii_entities else "None"
        pii_count = sum(pii_entities.values())

        # Mask PII in subject and body
        masked_subject = self.pii_processor.anonymize(subject) if subject else ""
        masked_body = self.pii_processor.anonymize(email_body) if email_body else ""

        # Create synthetic version (placeholders replaced with fake data)
        synthetic_subject = self.pii_processor.anonymize_with_synthetic(subject) if subject else ""
        synthetic_body = self.pii_processor.anonymize_with_synthetic(email_body) if email_body else ""

        # Extract threading information
        threading_info = self._extract_threading_info(message)

        # Extract From, To, CC from transport headers
        addresses = self._extract_addresses_from_headers(message)

        email_from = self._format_address_list(addresses["from"])
        email_to = self._format_address_list(addresses["to"])
        email_cc = self._format_address_list(addresses["cc"])

        # Anonymize email addresses
        email_from_masked = self.email_anonymizer.anonymize_address_list(email_from)
        email_to_masked = self.email_anonymizer.anonymize_address_list(email_to)
        email_cc_masked = self.email_anonymizer.anonymize_address_list(email_cc)

        # Get number of attachments
        no_of_attachments = 0
        try:
            if hasattr(message, 'number_of_attachments'):
                no_of_attachments = message.number_of_attachments or 0
            elif hasattr(message, 'attachments'):
                attachments = message.attachments
                if attachments is not None:
                    no_of_attachments = len(list(attachments)) if hasattr(attachments, '__iter__') else 0
        except Exception:
            no_of_attachments = 0

        # Log extracted addresses
        print(f"    From: {email_from_masked}")
        print(f"    To: {email_to_masked}")
        if email_cc_masked:
            print(f"    CC: {email_cc_masked}")

        return {
            "MessageId": getattr(message, 'identifier', '') or getattr(message, 'message_id', '') or "",
            "EmailReceivedDate": message.delivery_time,
            "EmailFrom": email_from_masked,
            "EmailTo": email_to_masked,
            "EmailCC": email_cc_masked,
            "OriginalEmailFrom": email_from,
            "OriginalEmailTo": email_to,
            "OriginalEmailCC": email_cc,
            "Subject": masked_subject,
            "EmailBody": masked_body,
            "SubjectSynthetic": synthetic_subject,
            "EmailBodySynthetic": synthetic_body,
            "OriginalSubject": subject,
            "OriginalEmailBody": email_body,
            "PIIEntitiesFound": pii_entities_str,
            "PIICount": pii_count,
            "NoOfAttachments": no_of_attachments,
            "ThreadMessageId": threading_info["message_id"],
            "ThreadId": threading_info["thread_id"],
            "ParentId": threading_info["parent_id"],
            "References": "; ".join(threading_info["references"]) if threading_info["references"] else "",
            "ReplyDepth": threading_info["reply_depth"]
        }

    def _write_batch_to_csv(self, messages: List[dict], output_base: str, batch_number: int) -> None:
        """Write a batch of messages to a separate CSV file."""
        if not messages:
            return

        # Create unique filename for this batch
        # Extract directory and base filename
        output_dir = os.path.dirname(output_base)
        base_name = os.path.basename(output_base)
        # Remove .csv extension if present
        if base_name.endswith('.csv'):
            base_name = base_name[:-4]

        # Create batch-specific filename
        batch_filename = f"{base_name}_batch{batch_number:04d}.csv"
        batch_filepath = os.path.join(output_dir, batch_filename)

        try:
            with open(batch_filepath, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'MessageId',
                    'EmailReceivedDate',
                    'EmailFromMasked',
                    'EmailToMasked',
                    'EmailCCMasked',
                    'SubjectMasked',
                    'EmailBodyMasked',
                    'SubjectSynthetic',
                    'EmailBodySynthetic',
                    'OriginalSubject',
                    'OriginalEmailBody',
                    'PIIEntitiesFound',
                    'PIICount',
                    'NoOfAttachments',
                    'ThreadMessageId',
                    'ThreadId',
                    'ParentId',
                    'References',
                    'ReplyDepth'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
                writer.writeheader()

                def sanitize_for_csv(value):
                    """Sanitize text for CSV compatibility."""
                    if value is None:
                        return ''
                    if not isinstance(value, str):
                        return value
                    # Replace double quotes with single quotes
                    value = value.replace('"', "'")
                    # Replace various newline types with space
                    return value.replace('\r\n', ' ').replace('\r', ' ').replace('\n', ' ')

                for msg in messages:
                    writer.writerow({
                        'MessageId': msg['MessageId'],
                        'EmailReceivedDate': msg['EmailReceivedDate'],
                        'EmailFromMasked': sanitize_for_csv(msg['EmailFrom']),
                        'EmailToMasked': sanitize_for_csv(msg.get('EmailTo', '')),
                        'EmailCCMasked': sanitize_for_csv(msg.get('EmailCC', '')),
                        'SubjectMasked': sanitize_for_csv(msg['Subject']),
                        'EmailBodyMasked': sanitize_for_csv(msg['EmailBody']),
                        'SubjectSynthetic': sanitize_for_csv(msg['SubjectSynthetic']),
                        'EmailBodySynthetic': sanitize_for_csv(msg['EmailBodySynthetic']),
                        'OriginalSubject': sanitize_for_csv(msg['OriginalSubject']),
                        'OriginalEmailBody': sanitize_for_csv(msg['OriginalEmailBody']),
                        'PIIEntitiesFound': sanitize_for_csv(msg['PIIEntitiesFound']),
                        'PIICount': msg['PIICount'],
                        'NoOfAttachments': msg['NoOfAttachments'],
                        'ThreadMessageId': sanitize_for_csv(msg.get('ThreadMessageId', '')),
                        'ThreadId': sanitize_for_csv(msg.get('ThreadId', '')),
                        'ParentId': sanitize_for_csv(msg.get('ParentId', '')),
                        'References': sanitize_for_csv(msg.get('References', '')),
                        'ReplyDepth': msg.get('ReplyDepth', 0)
                    })

            print(f"[CSV] Batch {batch_number} written: {len(messages)} messages to {batch_filename}")

        except Exception as e:
            print(f"[CSV] Error writing batch {batch_number}: {str(e)}")

    def list_all_folders(self, pst_path: str) -> List[str]:
        """List all folders in the PST file."""
        try:
            with PffArchive(pst_path) as archive:
                folders = []
                for folder in archive.folders():
                    folders.append(folder.name)
                return sorted(folders)
        except Exception as e:
            print(f"Error listing folders: {str(e)}")
            return []

    def read_all_folders(self, pst_path: str, max_messages_per_folder: int = 1000) -> Dict[str, List[dict]]:
        """Read and process messages from ALL folders in PST file."""
        try:
            with PffArchive(pst_path) as archive:
                all_results = {}
                
                print("Scanning all folders in PST...")
                folders = list(archive.folders())
                print(f"Found {len(folders)} folders")
                
                # Get all messages first
                all_messages = list(archive.messages())
                print(f"Total messages in PST: {len(all_messages)}")
                
                # Group messages by folder
                for idx, folder in enumerate(folders, 1):
                    folder_name = folder.name
                    print(f"\n[{idx}/{len(folders)}] Processing folder: {folder_name}")
                    
                    try:
                        messages = []
                        count = 0
                        
                        # Check each message to see if it belongs to this folder
                        for message in all_messages:
                            if count >= max_messages_per_folder:
                                break

                            try:
                                # Skip calendar messages (appointments, meetings, etc.)
                                if self._is_calendar_message(message):
                                    continue

                                # Try to match message to folder (libratom limitation)
                                # Process all messages for now
                                messages.append(self._process_message(message))
                                count += 1
                            except Exception as e:
                                continue
                        
                        if messages:
                            all_results[folder_name] = messages
                            print(f"  ✓ Processed {len(messages)} messages")
                        else:
                            print(f"  - No messages found")
                            
                    except Exception as e:
                        print(f"  ✗ Error processing folder: {str(e)}")
                        continue
                
                return all_results
                
        except Exception as e:
            print(f"Error reading PST file: {str(e)}")
            import traceback
            traceback.print_exc()
            return {}

    def read_all_messages(self, pst_path: str,
                          max_messages: int = None,
                          debug_first: bool = False,
                          log_per_message: bool = True,
                          output_csv: str = None,
                          batch_size: int = 5000) -> List[dict]:
        """Read all messages from PST file (not organized by folder)."""
        try:
            start_time = datetime.now()
            print(f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] Starting to process messages from PST...")
            if output_csv:
                print(f"[CSV] Output file: {output_csv} (batch size: {batch_size})")

            with PffArchive(pst_path) as archive:
                messages = []
                current_batch = []
                count = 0
                batch_number = 1
                last_timestamp = datetime.now()
                message_start_time = datetime.now()

                for message in archive.messages():
                    if max_messages is not None and count >= max_messages:
                        break
                    try:
                        # Skip calendar messages (appointments, meetings, etc.)
                        if self._is_calendar_message(message):
                            continue

                        message_start_time = datetime.now()

                        # Debug first message if requested
                        if debug_first and count == 0:
                            self._debug_message_properties(message)

                        # Process the message
                        processed_msg = self._process_message(message)
                        messages.append(processed_msg)
                        current_batch.append(processed_msg)
                        count += 1

                        # Calculate processing time for this message
                        message_end_time = datetime.now()
                        message_duration = (message_end_time - message_start_time).total_seconds()

                        # Per-message logging
                        if log_per_message:
                            pii_masked = "YES" if (processed_msg['Subject'] != processed_msg['OriginalSubject'] or
                                                  processed_msg['EmailBody'] != processed_msg['OriginalEmailBody']) else "NO"
                            subject_preview = processed_msg['Subject'][:50] if processed_msg['Subject'] else "(no subject)"
                            print(f"[{message_end_time.strftime('%H:%M:%S.%f')[:-3]}] "
                                  f"Message {count:4d} | "
                                  f"Time: {message_duration:.3f}s | "
                                  f"PII: {pii_masked:3s} | "
                                  f"Subject: {subject_preview}")

                        # Write batch to CSV when batch size is reached
                        if output_csv and len(current_batch) >= batch_size:
                            self._write_batch_to_csv(current_batch, output_csv, batch_number)
                            current_batch = []
                            batch_number += 1

                        # Print summary every 10 messages
                        if count % 10 == 0:
                            current_time = datetime.now()
                            elapsed = (current_time - last_timestamp).total_seconds()
                            total_elapsed = (current_time - start_time).total_seconds()
                            avg_time = elapsed / 10
                            print(f"{'─' * 80}")
                            print(f"[{current_time.strftime('%H:%M:%S')}] ✓ Processed {count} messages | "
                                  f"Last 10: {elapsed:.2f}s (avg: {avg_time:.3f}s/msg) | "
                                  f"Total: {total_elapsed:.2f}s")
                            print(f"{'─' * 80}")
                            last_timestamp = current_time

                    except Exception as e:
                        error_time = datetime.now()
                        print(f"[{error_time.strftime('%H:%M:%S.%f')[:-3]}] ✗ Error processing message {count}: {str(e)}")
                        continue

                # Write remaining messages in final batch
                if output_csv and current_batch:
                    self._write_batch_to_csv(current_batch, output_csv, batch_number)
                    print(f"[CSV] Final batch written")

                end_time = datetime.now()
                total_time = (end_time - start_time).total_seconds()
                print(f"\n{'═' * 80}")
                print(f"[{end_time.strftime('%Y-%m-%d %H:%M:%S')}] ✓ COMPLETED!")
                print(f"{'═' * 80}")
                print(f"Total messages processed: {len(messages)}")
                print(f"Total processing time: {total_time:.2f} seconds ({total_time/60:.2f} minutes)")
                if len(messages) > 0:
                    print(f"Average time per message: {total_time/len(messages):.3f} seconds")
                if output_csv:
                    print(f"CSV output saved to: {output_csv}")
                    print(f"Total batches written: {batch_number}")
                print(f"{'═' * 80}\n")
                return messages
                
        except Exception as e:
            print(f"Error reading PST file: {str(e)}")
            import traceback
            traceback.print_exc()
            return []

    def read_pst_folder(self, pst_path: str, folder_path: str = None) -> Optional[List[dict]]:
        """Read and process messages from a specific folder in PST file."""
        try:
            with PffArchive(pst_path) as archive:
                
                if folder_path:
                    target_folder = self._find_folder_by_path(archive, folder_path)
                    if not target_folder:
                        print(f"Folder '{folder_path}' not found.")
                        print("Available folders:")
                        for folder in archive.folders():
                            print(f"  - {folder.name}")
                        return None
                    
                    print(f"Found folder: {target_folder.name}")
                
                print("Processing all messages in PST...")
                messages = []
                count = 0
                
                for message in archive.messages():
                    if count >= 200:
                        break
                    try:
                        # Skip calendar messages (appointments, meetings, etc.)
                        if self._is_calendar_message(message):
                            continue

                        messages.append(self._process_message(message))
                        count += 1
                        if count % 100 == 0:
                            print(f"Processed {count} messages...")
                    except Exception as e:
                        print(f"Error processing message {count}: {str(e)}")
                        continue
                
                print(f"Total messages processed: {len(messages)}")
                return messages

        except Exception as e:
            print(f"Error reading PST file: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

if __name__ == "__main__":
    script_start = datetime.now()
    print(f"\n{'=' * 60}")
    print(f"SCRIPT STARTED AT: {script_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 60}\n")

    # Generate output filenames with timestamp
    timestamp = script_start.strftime('%Y%m%d_%H%M%S')
    email_mapping_csv = rf"C:\Code Repo\PII Masking Test\email_mapping_{timestamp}.csv"

    reader = PSTReader(email_mapping_csv=email_mapping_csv)
    pst_path = r"C:\Code Repo\PII Masking Test\mailbackup.pst"

    output_csv = rf"C:\Code Repo\PII Masking Test\pst_emails_masked_{timestamp}.csv"

    print("=" * 60)
    print("LISTING ALL FOLDERS")
    print("=" * 60)
    folder_start = datetime.now()
    folders = reader.list_all_folders(pst_path)
    folder_end = datetime.now()
    for folder in folders:
        print(f"  📁 {folder}")
    print(f"Folder listing completed in {(folder_end - folder_start).total_seconds():.2f} seconds")

    print("\n" + "=" * 60)
    print("READING ALL MESSAGES")
    print("=" * 60)
    all_messages = reader.read_all_messages(
        pst_path,
        max_messages=None,  # Process ALL messages (set to a number to limit)
        debug_first=False,  # Set to True to debug first message properties
        log_per_message=True,
        output_csv=output_csv,
        batch_size=2000  # Each batch creates a separate CSV file
    )
    
    summary_start = datetime.now()
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total messages processed: {len(all_messages)}")

    # Count messages where PII was masked (subject or body changed)
    pii_count = sum(1 for msg in all_messages
                   if msg['Subject'] != msg['OriginalSubject'] or
                      msg['EmailBody'] != msg['OriginalEmailBody'])
    print(f"Messages with PII masked: {pii_count}")

    print("\n" + "=" * 60)
    print("SAMPLE MESSAGES (First 20)")
    print("=" * 60)
    for idx, msg in enumerate(all_messages[:20], 1):
        print(f"\n[{idx}] MessageId: {msg['MessageId']}")
        print(f"EmailFrom (MASKED): {msg['EmailFrom']}")
        print(f"EmailFrom (ORIGINAL): {msg.get('OriginalEmailFrom', '')}")
        print(f"EmailTo (MASKED): {msg.get('EmailTo', '')}")
        print(f"EmailTo (ORIGINAL): {msg.get('OriginalEmailTo', '')}")
        if msg.get('EmailCC') or msg.get('OriginalEmailCC'):
            print(f"EmailCC (MASKED): {msg.get('EmailCC', '')}")
            print(f"EmailCC (ORIGINAL): {msg.get('OriginalEmailCC', '')}")
        print(f"EmailReceivedDate: {msg['EmailReceivedDate']}")

        # Show if PII was masked in subject
        if msg['Subject'] != msg['OriginalSubject']:
            print(f"Subject (MASKED): {msg['Subject']}")
            print(f"Subject (ORIGINAL): {msg['OriginalSubject']}")
        else:
            print(f"Subject: {msg['Subject']}")

        # Show if PII was masked in body
        masked_body_preview = msg['EmailBody'][:200] if len(msg['EmailBody']) > 200 else msg['EmailBody']
        original_body_preview = msg['OriginalEmailBody'][:200] if len(msg['OriginalEmailBody']) > 200 else msg['OriginalEmailBody']

        if msg['EmailBody'] != msg['OriginalEmailBody']:
            print(f"EmailBody (MASKED): {masked_body_preview}{'...' if len(msg['EmailBody']) > 200 else ''}")
            print(f"EmailBody (ORIGINAL): {original_body_preview}{'...' if len(msg['OriginalEmailBody']) > 200 else ''}")
        else:
            print(f"EmailBody: {masked_body_preview}{'...' if len(msg['EmailBody']) > 200 else ''}")

    summary_end = datetime.now()
    script_end = datetime.now()
    total_script_time = (script_end - script_start).total_seconds()

    print(f"\n{'=' * 60}")
    print("TIMING SUMMARY")
    print(f"{'=' * 60}")
    print(f"Script started:  {script_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Script ended:    {script_end.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total runtime:   {total_script_time:.2f} seconds ({total_script_time/60:.2f} minutes)")
    print(f"{'=' * 60}\n")  