import os
from pypdf import PdfReader

file_path = "uploads"

print("VISIONX PDF READER")
print("-------------------")

for file_name in os.listdir(file_path):

    if file_name.lower().endswith(".pdf"):

        full_path = os.path.join(file_path, file_name)

        reader = PdfReader(full_path)

        print("File Name:", file_name)
        print("Number of Pages:", len(reader.pages))

        text = ""

        for page in reader.pages:
            text += page.extract_text() or ""

        print("Extracted Text:")
        print(text)

        print("-------------------")