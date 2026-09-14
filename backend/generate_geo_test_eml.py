import os
from email.message import EmailMessage
import datetime

def generate_geo_eml():
    msg = EmailMessage()
    msg['Subject'] = 'Account Suspension Notice'
    msg['From'] = 'security@paypal-support-update.com'
    msg['To'] = 'victim@company.com'
    msg['Date'] = datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S -0000")
    
    # Inject a public, routable IP into the Received header.
    # We will use 185.220.101.46 (A known Tor exit node in Germany)
    # This will trigger the geo-locator and render the map pin in Germany.
    msg['Received'] = 'from mail.paypal-support-update.com ([185.220.101.46]) by mx.company.com with ESMTP id 12345; Mon, 14 Sep 2026 15:30:00 -0000'
    
    body = """Dear User,

We have detected unusual login activity on your account from a new location.
Please click the link below to verify your identity.

http://paypal-support-update.com/verify

Thank you,
Security Team"""

    msg.set_content(body)
    
    output_path = 'geo_test_sample.eml'
    with open(output_path, 'wb') as f:
        f.write(bytes(msg))
    
    print(f"Generated Geo Test EML saved to: {os.path.abspath(output_path)}")

if __name__ == '__main__':
    generate_geo_eml()
