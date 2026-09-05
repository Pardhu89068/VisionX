def detect_purpose(text):

    text = text.lower()

    job_keywords = [
        "resume",
        "cv",
        "curriculum vitae",
        "job",
        "experience",
        "skills",
        "work experience"
    ]

    education_keywords = [
        "student",
        "exam",
        "question paper",
        "marks",
        "college",
        "university",
        "semester",
        "assignment",
        "academic"
    ]

    finance_keywords = [
        "invoice",
        "bill",
        "transaction",
        "payment",
        "bank statement",
        "amount",
        "receipt"
    ]

    medical_keywords = [
        "medical",
        "patient",
        "diagnosis",
        "hospital",
        "doctor",
        "prescription",
        "blood test"
    ]

    for keyword in job_keywords:
        if keyword in text:
            return "Job"

    for keyword in education_keywords:
        if keyword in text:
            return "Education"

    for keyword in finance_keywords:
        if keyword in text:
            return "Finance"

    for keyword in medical_keywords:
        if keyword in text:
            return "Medical"

    return "General"