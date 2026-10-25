import os
from email.message import EmailMessage
import datetime

def generate_safe_eml():
    msg = EmailMessage()
    msg['Subject'] = 'Your Job Offer: Senior Security Engineer'
    msg['From'] = 'hr@brand-new-startup-2026.io'
    msg['To'] = 'candidate@company.com'
    
    # Set date to today
    msg['Date'] = datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S -0000")
    
    # Add a custom header to simulate failing SPF due to new/misconfigured startup infrastructure
    msg['Received-SPF'] = 'Fail (domain of brand-new-startup-2026.io does not designate 192.0.2.1 as permitted sender)'
    
    body = """Hi there,

It was great speaking with you yesterday! We are absolutely thrilled to extend an offer for you to join us as our Founding Security Engineer.

As a newly launched startup, we are moving fast. Please review the attached offer letter outlining your compensation, equity, and benefits. 

Take your time to read it over, and let us know if you have any questions before signing. We aren't rushing you, but we'd love to get you onboarded next month!

Best regards,
Sarah Jenkins
Head of People
Brand New Startup Inc."""

    msg.set_content(body)
    
    # A perfectly valid, harmless, minimalist PDF file in bytes
    minimal_pdf_bytes = b"%PDF-1.4\n1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj\n2 0 obj <</Type /Pages /Kids [3 0 R] /Count 1>> endobj\n3 0 obj <</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>> endobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000056 00000 n\n0000000111 00000 n\ntrailer <</Size 4 /Root 1 0 R>>\nstartxref\n190\n%%EOF\n"
    
    msg.add_attachment(minimal_pdf_bytes, maintype='application', subtype='pdf', filename='Offer_Letter_2026.pdf')
    
    output_path = 'safe_startup_offer.eml'
    with open(output_path, 'wb') as f:
        f.write(bytes(msg))
    
    print(f"Generated EML saved to: {os.path.abspath(output_path)}")

if __name__ == '__main__':
    generate_safe_eml()
