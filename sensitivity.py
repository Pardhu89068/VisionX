def detect_sensitivity(text):

    text = text.lower()

    high_keywords = [
        "aadhaar",
        "passport",
        "account number",
        "bank account",
        "credit card",
        "debit card",
        "password",
        "otp",
        "medical diagnosis",
        "patient"
    ]

    medium_keywords = [
        "student",
        "marks",
        "hall ticket",
        "exam",
        "college",
        "university",
        "resume",
        "phone number",
        "email"
    ]

    for keyword in high_keywords:
        if keyword in text:
            return "High"

    for keyword in medium_keywords:
        if keyword in text:
            return "Medium"

    return "Low"