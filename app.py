import streamlit as st
import joblib
import pandas as pd
import re
from urllib.parse import urlparse

# THIS LINE MUST BE HERE (right after imports, before any Streamlit content)
st.set_page_config(page_title="Phishing URL Detector", page_icon=":shield:", layout="centered")

@st.cache_resource
def load_model():
    return joblib.load("phishing_rf_model.pkl")

model = load_model()

def extract_url_features(url):
    uses_https = int(urlparse(url).scheme == 'https')
    url_length = len(url)
    num_dots = url.count('.')
    has_ip = int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', urlparse(url).netloc)))
    parsed = urlparse(url)
    has_at = '@' in url
    double_slash_in_path = '//' in parsed.path
    has_suspicious_chars = int(has_at or double_slash_in_path)
    return {
        'uses_https': uses_https,
        'url_length': url_length,
        'num_dots': num_dots,
        'has_ip': has_ip,
        'has_suspicious_chars': has_suspicious_chars
    }

st.title("🔎 Phishing URL Detector")
st.write("Enter a URL below to check if it's malicious or safe.")

url = st.text_input("Enter URL", "http://example.com")

if st.button("Check URL"):
    if url:
        features = extract_url_features(url)
        X = pd.DataFrame([features])
        pred = model.predict(X)[0]
        pred_proba = model.predict_proba(X)[0][1]
        color = "red" if pred else "green"
        verdict = "Malicious (Phishing!)" if pred else "Safe"
        st.markdown(f"### Result: <span style='color:{color}'>{verdict}</span>", unsafe_allow_html=True)
        st.write(f"**Prediction Confidence:** {pred_proba:.2%}")
        st.subheader("Extracted Features:")
        st.json(features)
    else:
        st.warning("Please enter a valid URL.")

