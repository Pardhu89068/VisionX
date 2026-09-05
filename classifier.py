def classify_text(text):

    text = text.lower()

    academic_keywords = [
        "exam",
        "examination",
        "hall ticket",
        "student",
        "college",
        "university",
        "semester",
        "marks",
        "course",
        "degree"
    ]

    career_keywords = [
        "resume",
        "cv",
        "job",
        "experience",
        "skills",
        "career",
        "employment",
        "interview"
    ]

    financial_keywords = [
        "bank",
        "account number",
        "transaction",
        "salary",
        "payment",
        "invoice",
        "amount",
        "balance"
    ]

    identity_keywords = [
        "aadhaar",
        "passport",
        "identity",
        "date of birth",
        "address",
        "id number"
    ]

    medical_keywords = [
        "hospital",
        "doctor",
        "patient",
        "medicine",
        "medical",
        "diagnosis",
        "prescription"
    ]

    academic_score = sum(
        keyword in text for keyword in academic_keywords
    )

    career_score = sum(
        keyword in text for keyword in career_keywords
    )

    financial_score = sum(
        keyword in text for keyword in financial_keywords
    )

    identity_score = sum(
        keyword in text for keyword in identity_keywords
    )

    medical_score = sum(
        keyword in text for keyword in medical_keywords
    )

    scores = {
        "Academic": academic_score,
        "Career": career_score,
        "Financial": financial_score,
        "Identity": identity_score,
        "Medical": medical_score
    }

    category = max(scores, key=scores.get)

    if scores[category] == 0:
        category = "General"

    return category