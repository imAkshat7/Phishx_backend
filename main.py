from fastapi import FastAPI
import pickle
import pandas as pd
import re
import tldextract
import json
import requests
from bs4 import BeautifulSoup

# Load the trained model
with open("rf_model.pkl", "rb") as model_file:
    model = pickle.load(model_file)

# Load blacklist from JSON file
BLACKLIST_FILE = "blacklist.json"

def load_blacklist():
    """Load blacklist from file."""
    try:
        with open(BLACKLIST_FILE, "r") as file:
            return set(json.load(file))  # Convert list to set for fast lookup
    except FileNotFoundError:
        return set()  # Return empty set if file not found

def save_blacklist(blacklist):
    """Save blacklist to file."""
    with open(BLACKLIST_FILE, "w") as file:
        json.dump(list(blacklist), file, indent=4)

blacklist_urls = load_blacklist()  # Load blacklist on startup

app = FastAPI()

# Function to check for login forms in the URL's HTML
def check_html_features(url):
    """Fetch and analyze the page to extract form-based phishing features."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        has_submit_button = 1 if soup.find("button", {"type": "submit"}) else 0
        has_password_field = 1 if soup.find("input", {"type": "password"}) else 0
        has_hidden_fields = 1 if soup.find("input", {"type": "hidden"}) else 0
        has_external_form_submit = 0

        # Check if form action goes to an external site (possible phishing)
        for form in soup.find_all("form"):
            action = form.get("action")
            if action and not action.startswith("/") and tldextract.extract(action).domain not in url:
                has_external_form_submit = 1
                break

        return has_submit_button, has_password_field, has_hidden_fields, has_external_form_submit
    except:
        return 0, 0, 0, 0  # Default if request fails

# Feature extraction function
def extract_features(url):
    """Extract features from a URL for prediction."""
    extracted = tldextract.extract(url)
    has_submit, has_password, has_hidden, has_external = check_html_features(url)

    features = {
        "URLLength": len(url),
        "DomainLength": len(extracted.domain),
        "TLD": len(extracted.suffix),
        "CharContinuationRate": sum(1 for c in url if c.isalpha()) / max(len(url), 1),  # Avoid ZeroDivisionError
        "TLDLegitimateProb": 0.5,  # Placeholder, update if you have actual data
        "URLCharProb": sum(c.isalnum() for c in url) / max(len(url), 1),
        "SpacialCharRatioInURL": len(re.findall(r"[!@#$%^&*(),.?\":{}|<>]", url)) / max(len(url), 1),
        "IsHTTPS": 1 if url.startswith("https") else 0,
        "HasExternalFormSubmit": has_external,
        "HasSubmitButton": has_submit,
        "HasHiddenFields": has_hidden,
        "HasPasswordField": has_password,
        "Bank": 1 if "bank" in url.lower() else 0,
        "Pay": 1 if "pay" in url.lower() else 0,
    }

    print("Extracted Features:", features)  # Debugging feature extraction
    return pd.DataFrame([features])  # Convert to DataFrame

@app.get("/")
def home():
    return {"message": "Phishing Detection API is running!"}

@app.post("/predict/")
def predict_phishing(url: str):
    """Predict if a URL is phishing or legitimate, checking against the blacklist first."""

    # Step 1: Extract features first, regardless of blacklist
    features_df = extract_features(url)

    # Step 2: If URL is blacklisted, return phishing result with features
    if url in blacklist_urls:
        return {
            "url": url,
            "prediction": "Phishing",
            "extracted_features": features_df.to_dict(orient="records")[0]
        }

    # Step 3: Ensure feature order matches model
    try:
        features_df = features_df[model.feature_names_in_]
    except AttributeError:
        return {"error": "Model does not contain feature_names_in_, check training pipeline."}

    print("Final Feature DataFrame Before Prediction:\n", features_df)  # Debugging before prediction

    # Step 4: Predict
    prediction = model.predict(features_df)[0]
    result = "Phishing" if prediction == 1 else "Legitimate"

    return {
        "url": url,
        "prediction": result,
        "extracted_features": features_df.to_dict(orient="records")[0]  # Send all extracted features in response
    }

@app.post("/add_blacklist/")
def add_to_blacklist(url: str):
    """Add a new phishing URL to the blacklist."""
    blacklist_urls.add(url.strip())  # Trim spaces and add to set
    save_blacklist(blacklist_urls)
    return {"message": f"URL '{url}' added to blacklist successfully."}

@app.get("/get_blacklist/")
def get_blacklist():
    """Retrieve the current blacklist."""
    return {"blacklisted_urls": list(blacklist_urls)}
