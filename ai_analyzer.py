"""
VisionX Claude AI document analyzer.

Uses the Anthropic Claude API when ANTHROPIC_API_KEY is configured.
Falls back to the existing local rule-based analysis if Claude is
unavailable, so the application does not completely fail.
"""

import json
import os


def _rule_based_analysis(text):
    text_lower = (text or "").lower()

    if "resume" in text_lower or "curriculum vitae" in text_lower:
        return {"document_type": "Resume", "confidence": "High"}

    if "question paper" in text_lower or "examination" in text_lower:
        return {"document_type": "Exam Document", "confidence": "High"}

    if "invoice" in text_lower or "bill" in text_lower:
        return {"document_type": "Financial Document", "confidence": "High"}

    if "medical report" in text_lower or "diagnosis" in text_lower:
        return {"document_type": "Medical Document", "confidence": "High"}

    return {"document_type": "General Document", "confidence": "Medium"}


def _extract_json(text):
    """Extract a JSON object even if the model adds surrounding text."""
    text = (text or "").strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")

    if start != -1 and end > start:
        return json.loads(text[start:end + 1])

    raise ValueError("Claude did not return valid JSON.")


def ai_analyze_document(text):
    """
    Analyze document text with Claude.

    Environment variables:
      ANTHROPIC_API_KEY - required for Claude
      ANTHROPIC_MODEL   - optional; defaults to a Claude Sonnet model
    """

    text = (text or "").strip()

    if not text:
        return {
            "document_type": "General Document",
            "confidence": "Low",
        }

    api_key = os.getenv("ANTHROPIC_API_KEY")

    # Keep the request bounded so very large documents do not create
    # unnecessarily large API requests/costs.
    document_text = text[:40000]

    if not api_key:
        return _rule_based_analysis(text)

    try:
        from anthropic import Anthropic

        client = Anthropic(api_key=api_key)

        model = os.getenv(
            "ANTHROPIC_MODEL",
            "claude-sonnet-4-20250514"
        )

        response = client.messages.create(
            model=model,
            max_tokens=500,
            temperature=0,
            system=(
                "You are the document analysis engine for VisionX, "
                "a personal document lifecycle management system. "
                "Analyze the supplied document text. Return ONLY valid JSON "
                "with exactly these fields: document_type and confidence. "
                "document_type should be a short useful category such as "
                "Resume, Academic Document, Certificate, Identity Document, "
                "Financial Document, Employment Document, Medical Document, "
                "Legal Document, or General Document. "
                "confidence must be one of: Low, Medium, High, Very High."
            ),
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Analyze this document:\n\n"
                        + document_text
                    ),
                }
            ],
        )

        raw = "".join(
            block.text
            for block in response.content
            if getattr(block, "type", None) == "text"
        )

        result = _extract_json(raw)

        document_type = str(
            result.get("document_type", "General Document")
        ).strip()

        confidence = str(
            result.get("confidence", "Medium")
        ).strip()

        allowed_confidence = {
            "Low",
            "Medium",
            "High",
            "Very High",
        }

        if confidence not in allowed_confidence:
            confidence = "Medium"

        return {
            "document_type": document_type[:100] or "General Document",
            "confidence": confidence,
        }

    except Exception as error:
        # Keep VisionX usable if the API is temporarily unavailable,
        # the model name changes, or the package is not installed.
        print("Claude AI analysis unavailable:", error)
        return _rule_based_analysis(text)
