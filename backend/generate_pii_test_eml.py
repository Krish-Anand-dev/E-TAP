import os
from email.message import EmailMessage
import datetime

def generate_pii_eml():
    msg = EmailMessage()
    msg['Subject'] = 'URGENT: Verify Your KYC Details and Aadhaar'
    msg['From'] = 'compliance@fake-bank-security.com'
    msg['To'] = 'victim@company.com'
    
    msg['Date'] = datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S -0000")
    
    body = """Dear Customer,

We have detected unusual activity on your account. To prevent immediate suspension, you must reply to this email with your KYC details.

Please verify the following information we have on file:
- Primary Email: personal.account@gmail.com
- Phone Number: +91 9876543210
- Alternate Phone: 555-012-3456
- Aadhaar Number: 1234 5678 9012
- PAN Card: ABCDE1234F
- Social Security Number (US): 987-65-4321
- Credit Card on file: 4111-2222-3333-4444

If you do not contact our compliance officer at compliance.officer@fake-bank-security.com within 24 hours, your funds will be frozen.

Regards,
Fraud Prevention Team"""

    msg.set_content(body)
    
    output_path = 'pii_test_sample.eml'
    with open(output_path, 'wb') as f:
        f.write(bytes(msg))
    
    print(f"Generated PII Test EML saved to: {os.path.abspath(output_path)}")

if __name__ == '__main__':
    generate_pii_eml()
