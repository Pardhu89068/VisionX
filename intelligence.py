# ==========================================
# VISIONX — INTELLIGENCE ENGINE V2
# ==========================================

import re


# ==========================================
# TEXT NORMALIZATION
# ==========================================

def normalize_text(text):
    if not text:
        return ""

    text = str(text)

    text = text.replace("\x00", " ")

    text = re.sub(r"\s+", " ", text)

    return text.strip()


# ==========================================
# DOCUMENT TYPE DETECTION
# ==========================================

def detect_document_type(text):
    text_lower = normalize_text(text).lower()

    rules = [
        (
            "Resume / CV",
            [
                "curriculum vitae",
                "resume",
                "professional summary",
                "work experience",
                "employment history",
                "technical skills",
                "career objective",
            ],
        ),
        (
            "Academic Document",
            [
                "semester",
                "student",
                "university",
                "college",
                "examination",
                "hall ticket",
                "marks",
                "course",
                "subject",
            ],
        ),
        (
            "Financial Document",
            [
                "bank statement",
                "account number",
                "transaction",
                "invoice",
                "payment",
                "balance",
                "amount due",
                "receipt",
            ],
        ),
        (
            "Medical Document",
            [
                "medical report",
                "patient",
                "diagnosis",
                "prescription",
                "hospital",
                "doctor",
                "clinical",
                "medicine",
            ],
        ),
        (
            "Identity Document",
            [
                "aadhaar",
                "passport",
                "identity card",
                "identity number",
                "date of birth",
                "government id",
            ],
        ),
        (
            "Employment Document",
            [
                "offer letter",
                "appointment letter",
                "joining date",
                "employee id",
                "employment",
                "salary",
                "designation",
            ],
        ),
        (
            "Certificate",
            [
                "certificate",
                "certification",
                "successfully completed",
                "awarded to",
                "achievement",
            ],
        ),
    ]

    scores = {}

    for document_type, keywords in rules:
        score = 0

        for keyword in keywords:
            if keyword in text_lower:
                score += 1

        scores[document_type] = score

    best_type = max(
        scores,
        key=scores.get
    )

    best_score = scores[best_type]

    if best_score == 0:
        return "General Document"

    return best_type


# ==========================================
# CONFIDENCE SCORE
# ==========================================

def calculate_confidence(text):
    text_lower = normalize_text(text).lower()

    if not text_lower:
        return 0

    keyword_groups = [
        [
            "resume",
            "curriculum vitae",
            "work experience",
            "professional summary",
        ],
        [
            "student",
            "college",
            "university",
            "semester",
            "examination",
        ],
        [
            "bank",
            "transaction",
            "invoice",
            "payment",
            "account number",
        ],
        [
            "patient",
            "diagnosis",
            "hospital",
            "prescription",
            "medical report",
        ],
        [
            "aadhaar",
            "passport",
            "identity",
            "government id",
        ],
    ]

    matched_groups = 0
    matched_keywords = 0

    for group in keyword_groups:
        group_matches = 0

        for keyword in group:
            if keyword in text_lower:
                group_matches += 1

        if group_matches > 0:
            matched_groups += 1
            matched_keywords += group_matches

    if matched_keywords == 0:
        return 45

    confidence = 55 + (
        matched_keywords * 8
    ) + (
        matched_groups * 5
    )

    return min(
        confidence,
        99
    )


# ==========================================
# RISK FLAG DETECTION
# ==========================================

def detect_risk_flags(text):
    text_lower = normalize_text(text).lower()

    flags = []

    patterns = {
        "Aadhaar / Government ID": [
            "aadhaar",
            "passport",
            "government id",
            "identity number",
        ],
        "Bank / Financial Data": [
            "account number",
            "bank account",
            "bank statement",
            "credit card",
            "debit card",
        ],
        "Contact Information": [
            "phone number",
            "mobile number",
            "email",
            "@",
        ],
        "Medical Information": [
            "diagnosis",
            "patient",
            "medical report",
            "prescription",
        ],
        "Authentication Data": [
            "password",
            "otp",
            "verification code",
        ],
        "Personal Information": [
            "date of birth",
            "address",
            "father name",
            "mother name",
        ],
    }

    for label, keywords in patterns.items():

        found = False

        for keyword in keywords:
            if keyword in text_lower:
                found = True
                break

        if found:
            flags.append(label)

    return flags


# ==========================================
# KEY INFORMATION DETECTION
# ==========================================

def detect_key_information(text):
    text_lower = normalize_text(text).lower()

    information = []

    patterns = {
        "Email address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",

        "Phone number": r"\b(?:\+91[\s-]?)?[6-9]\d{9}\b",

        "Date": r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",

        "Percentage": r"\b\d{1,3}(?:\.\d+)?\s?%\b",
    }

    for label, pattern in patterns.items():

        matches = re.findall(
            pattern,
            text
        )

        if matches:
            information.append(label)

    keyword_information = {
        "Aadhaar number": [
            "aadhaar",
        ],
        "Passport information": [
            "passport",
        ],
        "Bank account information": [
            "account number",
            "bank account",
        ],
        "Student information": [
            "student",
            "roll number",
            "registration number",
        ],
        "Employment information": [
            "work experience",
            "employment",
            "designation",
        ],
    }

    for label, keywords in keyword_information.items():

        for keyword in keywords:

            if keyword in text_lower:

                if label not in information:
                    information.append(label)

                break

    return information


# ==========================================
# RECOMMENDED ACTION
# ==========================================

def recommend_action(
    sensitivity,
    risk_flags,
    retention
):
    if sensitivity == "High":
        return "Move to Secure Vault"

    if "Authentication Data" in risk_flags:
        return "Review Immediately"

    if "Aadhaar / Government ID" in risk_flags:
        return "Store Securely"

    if "Bank / Financial Data" in risk_flags:
        return "Store Securely"

    if sensitivity == "Medium":
        return "Keep with Protection"

    if retention == "Archive":
        return "Archive"

    if retention == "Review":
        return "Review Later"

    return "Keep"


# ==========================================
# INTELLIGENCE SUMMARY
# ==========================================

def generate_summary(
    document_type,
    category,
    purpose,
    sensitivity,
    risk_flags
):
    if risk_flags:
        risk_text = ", ".join(
            risk_flags[:3]
        )

        return (
            f"This appears to be a {document_type.lower()} "
            f"related to {purpose.lower()}. "
            f"The system detected {sensitivity.lower()} "
            f"sensitivity with potential exposure involving "
            f"{risk_text}."
        )

    return (
        f"This appears to be a {document_type.lower()} "
        f"classified under {category.lower()} use. "
        f"The detected purpose is {purpose.lower()} "
        f"and no major sensitive-data indicators were found."
    )


# ==========================================
# MASTER INTELLIGENCE FUNCTION
# ==========================================

def generate_intelligence(
    text,
    category="General",
    sensitivity="Low",
    purpose="General",
    retention="Review"
):
    text = normalize_text(text)

    document_type = detect_document_type(
        text
    )

    confidence = calculate_confidence(
        text
    )

    risk_flags = detect_risk_flags(
        text
    )

    key_information = detect_key_information(
        text
    )

    recommended_action = recommend_action(
        sensitivity,
        risk_flags,
        retention
    )

    summary = generate_summary(
        document_type,
        category,
        purpose,
        sensitivity,
        risk_flags
    )

    return {
        "document_type": document_type,
        "confidence": confidence,
        "confidence_label": (
            "Very High"
            if confidence >= 90
            else "High"
            if confidence >= 75
            else "Medium"
            if confidence >= 55
            else "Low"
        ),
        "risk_flags": risk_flags,
        "risk_count": len(risk_flags),
        "key_information": key_information,
        "recommended_action": recommended_action,
        "summary": summary,
    }