def recommend_retention(category, sensitivity, purpose):

    if sensitivity == "High":
        return "Keep Securely"

    if sensitivity == "Medium":
        return "Keep"

    if category == "Academic":
        return "Archive"

    if purpose == "Job":
        return "Keep"

    return "Review"