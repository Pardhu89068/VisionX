import os
from pypdf import PdfReader

from classifier import classify_text
from sensitivity import detect_sensitivity
from purpose import detect_purpose
from retention import recommend_retention


UPLOAD_FOLDER = "uploads"

print("VISIONX FILE ANALYSIS")
print("=====================")


for file_name in os.listdir(UPLOAD_FOLDER):

    if file_name.lower().endswith(".pdf"):

        full_path = os.path.join(UPLOAD_FOLDER, file_name)

        reader = PdfReader(full_path)

        text = ""

        for page in reader.pages:
            text += page.extract_text() or ""

        category = classify_text(text)

        sensitivity = detect_sensitivity(text)

        purpose = detect_purpose(text)

        retention = recommend_retention(
            category,
            sensitivity,
            purpose
        )

        print("File Name:", file_name)
        print("Category:", category)
        print("Sensitivity:", sensitivity)
        print("Purpose:", purpose)
        print("Retention:", retention)
        print("---------------------")