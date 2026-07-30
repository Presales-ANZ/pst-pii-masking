import win32com.client
import os
import csv

def send_email(recipient, subject, body, attachments=None):
    """Send an email with optional attachments.
    
    Args:
        recipient: Email address or list of addresses
        subject: Email subject
        body: Email body text
        attachments: Optional path or list of paths to attach
    """
    try:
        outlook = win32com.client.Dispatch("Outlook.Application")
        mail = outlook.CreateItem(0)
        
        mail.To = ";".join(recipient) if isinstance(recipient, list) else recipient
        mail.Subject = subject
        mail.Body = body
        
        if attachments:
            if isinstance(attachments, str):
                attachments = [attachments]
            for file in attachments:
                if os.path.exists(file):
                    mail.Attachments.Add(file)
        
        mail.Send()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# Example usage:
if __name__ == "__main__":
    csv_file_path = 'emails.csv'
    recipient_email = "someone@example.com"  # Set the recipient email address here

    try:
        with open(csv_file_path, mode='r', newline='', encoding='utf-8') as csvfile:
            email_reader = csv.reader(csvfile)
            next(email_reader)  # Skip header row
            for row in email_reader:
                if len(row) >= 2:
                    subject = row[0]
                    body = row[1]
                    print(f"Sending email with subject: {subject}")
                    send_email(
                        recipient=recipient_email,
                        subject=subject,
                        body=body
                    )
    except FileNotFoundError:
        print(f"Error: The file '{csv_file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")