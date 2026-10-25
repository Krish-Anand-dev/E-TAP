import re

def redact_sensitive_data(text: str) -> str:
    """
    Masks Personally Identifiable Information (PII) from text strings.
    Used for GDPR/Privacy compliance before saving email contents to the database.
    """
    if not text or not isinstance(text, str):
        return text
        
    # 1. Mask Social Security Numbers (SSN: 123-45-6789)
    text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED_SSN]', text)
    
    # 2. Mask Credit Card Numbers (16 digits with or without spaces/dashes)
    text = re.sub(r'\b(?:\d[ -]*?){13,16}\b', '[REDACTED_CREDIT_CARD]', text)
    
    # 3. Mask Phone Numbers (Basic US formats & Indian +91 formats)
    text = re.sub(r'\b(?:\+?91[\-\s]?)?[6789]\d{9}\b', '[REDACTED_PHONE_IN]', text)
    text = re.sub(r'\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', '[REDACTED_PHONE_US]', text)
    
    # 4. Mask Indian Aadhaar Numbers (12 digits, often formatted as XXXX XXXX XXXX)
    text = re.sub(r'\b\d{4}[ -]?\d{4}[ -]?\d{4}\b', '[REDACTED_AADHAAR]', text)
    
    # 5. Mask Indian PAN Cards (5 Letters, 4 Numbers, 1 Letter)
    text = re.sub(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b', '[REDACTED_PAN_CARD]', text)
    
    # 6. Mask Email Addresses in the body
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '[REDACTED_EMAIL]', text)
    
    return text
