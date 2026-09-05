def ai_analyze_document(text):
    """
    AI-ready document analysis function.

    Currently this function returns a basic
    rule-based result. Later, an AI model
    can be connected here.
    """

    text = text.lower()

    if "resume" in text or "curriculum vitae" in text:
        return {
            "document_type": "Resume",
            "confidence": "High"
        }

    if "question paper" in text or "examination" in text:
        return {
            "document_type": "Exam Document",
            "confidence": "High"
        }

    if "invoice" in text or "bill" in text:
        return {
            "document_type": "Financial Document",
            "confidence": "High"
        }

    if "medical report" in text or "diagnosis" in text:
        return {
            "document_type": "Medical Document",
            "confidence": "High"
        }

    return {
        "document_type": "General Document",
        "confidence": "Medium"
    }