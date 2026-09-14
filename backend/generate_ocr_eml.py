import email
from email.message import EmailMessage
import numpy as np
import cv2
import os

def create_fake_phishing_image():
    # Create a blank white image
    img = np.ones((300, 600, 3), dtype=np.uint8) * 255
    
    # Add some text that OCR should pick up
    font = cv2.FONT_HERSHEY_SIMPLEX
    cv2.putText(img, "URGENT: ACCOUNT SUSPENDED", (20, 50), font, 1, (0, 0, 255), 2)
    cv2.putText(img, "Please verify your billing details", (20, 100), font, 0.8, (0, 0, 0), 2)
    cv2.putText(img, "within 24 hours to avoid closure.", (20, 140), font, 0.8, (0, 0, 0), 2)
    cv2.putText(img, "Click here: http://secure-update-billing.com", (20, 200), font, 0.7, (255, 0, 0), 2)
    cv2.putText(img, "BTC Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", (20, 260), font, 0.5, (0, 0, 0), 1)

    # Encode to PNG
    _, buffer = cv2.imencode('.png', img)
    return buffer.tobytes()

def generate_eml():
    msg = EmailMessage()
    msg['Subject'] = 'Urgent: Account Action Required'
    msg['From'] = 'billing@secure-service-notification.com'
    msg['To'] = 'victim@company.com'
    msg.set_content("Please see the attached document regarding your account status.")
    
    img_data = create_fake_phishing_image()
    
    msg.add_attachment(img_data, maintype='image', subtype='png', filename='account_notice.png')
    
    output_path = 'ocr_test_sample.eml'
    with open(output_path, 'wb') as f:
        f.write(bytes(msg))
    
    print(f"Generated EML saved to: {os.path.abspath(output_path)}")

if __name__ == '__main__':
    generate_eml()
