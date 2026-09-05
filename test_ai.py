import os

from pypdf import PdfReader

from ai_analyzer import ai_analyze_document


UPLOAD_FOLDER = "uploads"

print("VISIONX AI ANALYZER TEST")
print("========================")


for file_name in os.listdir(UPLOAD_FOLDER):

    if file_name.lower().endswith(".pdf"):

        file_path = os.path.join(
            UPLOAD_FOLDER,
            file_name
        )

        reader = PdfReader(file_path)

        text = ""

        for page in reader.pages:
            text += page.extract_text() or ""

        result = ai_analyze_document(text)

        print("File Name:", file_name)
        print("Document Type:", result["document_type"])
        print("Confidence:", result["confidence"])
        print("------------------------")