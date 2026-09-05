import os
from pypdf import PdfReader
from classifier import classify_text

UPLOAD_FOLDER = "uploads"

print("VISIONX FILE ANALYSIS")
print("---------------------")

for file_name in os.listdir(UPLOAD_FOLDER):

    if file_name.lower().endswith(".pdf"):

        full_path = os.path.join(UPLOAD_FOLDER, file_name)

        reader = PdfReader(full_path)

        text = ""

        for page in reader.pages:
            text += page.extract_text() or ""

        category = classify_text(text)

        print("File Name:", file_name)
        print("Category:", category)
        print("---------------------")