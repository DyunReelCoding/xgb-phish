import pickle
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import numpy as np

# Load the trained model
with open('xg_phishing.pkl', 'rb') as file:
    model = pickle.load(file)

# Define feature extraction logic
def extract_features(url):
    features = {}

    # Parse the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path

    # Feature extraction
    features['google_index'] = 1 if "google.com" in url else 0
    features['nb_qm'] = url.count('?')
    features['nb_www'] = url.count('www')
    features['ratio_digits_host'] = sum(c.isdigit() for c in domain) / len(domain) if domain else 0
    # features['page_rank'] = 0  # Placeholder, requires a page rank API
    features['suspecious_tld'] = 1 if domain.endswith(('.tk', '.ml', '.ga', '.cf', '.gq')) else 0
    # features['nb_hyperlinks'] = 0  # Placeholder, requires HTML parsing
    features['phish_hints'] = 1 if "phish" in url or "secure" in url else 0
    features['nb_colon'] = url.count(':')
    features['domain_in_brand'] = 1 if "brand" in domain else 0
    features['nb_space'] = url.count(' ')
    # features['statistical_report'] = 0  # Placeholder, external sources needed
    # features['web_traffic'] = 0  # Placeholder, requires web traffic data
    features['nb_hyphens'] = url.count('-')
    features['shortening_service'] = 1 if "bit.ly" in url or "tinyurl.com" in url else 0
    features['nb_underscore'] = url.count('_')
    features['longest_word_path'] = max(len(word) for word in path.split('/')) if path else 0
    features['ip'] = 1 if any(char.isdigit() for char in domain.split('.')) else 0
    # features['domain_in_title'] = 0  # Placeholder, requires HTML parsing
    features['nb_eq'] = url.count('=')
    features['nb_percent'] = url.count('%')
    features['length_words_raw'] = sum(len(word) for word in url.split('/')) / len(url.split('/')) if url.split('/') else 0
    features['nb_slash'] = url.count('/')
    features['longest_words_raw'] = max(len(word) for word in url.split('/')) if url.split('/') else 0
    features['nb_dots'] = url.count('.')
    # features['domain_age'] = 0  # Placeholder, requires WHOIS API
    features['shortest_word_host'] = min(len(word) for word in domain.split('.')) if domain.split('.') else 0
    features['length_hostname'] = len(domain)
    # features['empty_title'] = 0  # Placeholder, requires HTML parsing
    features['nb_com'] = url.count('com')
    # features['ratio_extHyperlinks'] = 0  # Placeholder, requires HTML parsing
    features['shortest_word_path'] = min(len(word) for word in path.split('/')) if path.split('/') else 0
    features['char_repeat'] = max(url.count(char) for char in set(url))
    features['tld_in_path'] = 1 if any(tld in path for tld in ['.com', '.net', '.org']) else 0
    features['length_url'] = len(url)
    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url) if url else 0
    features['prefix_suffix'] = 1 if '-' in domain else 0
    # features['external_favicon'] = 0  # Placeholder, requires HTML parsing
    # features['safe_anchor'] = 0  # Placeholder, requires HTML parsing
    features['nb_and'] = url.count('&')
    # features['domain_with_copyright'] = 0  # Placeholder, requires HTML parsing
    # features['ratio_extRedirection'] = 0  # Placeholder, requires HTML parsing
    # features['ratio_extMedia'] = 0  # Placeholder, requires HTML parsing
    # features['nb_extCSS'] = 0  # Placeholder, requires HTML parsing
    # features['ratio_extErrors'] = 0  # Placeholder, requires HTML parsing
    features['shortest_words_raw'] = min(len(word) for word in url.split('/')) if url.split('/') else 0
    features['https_token'] = 1 if 'https' in domain else 0
    # features['ratio_intHyperlinks'] = 0  # Placeholder, requires HTML parsing
    features['avg_words_raw'] = np.mean([len(word) for word in url.split('/')]) if url.split('/') else 0
    # features['domain_registration_length'] = 0  # Placeholder, requires WHOIS API
    # features['links_in_tags'] = 0  # Placeholder, requires HTML parsing
    # features['whois_registered_domain'] = 0  # Placeholder, requires WHOIS API
    features['avg_word_path'] = np.mean([len(word) for word in path.split('/')]) if path.split('/') else 0
    # features['ratio_intMedia'] = 0  # Placeholder, requires HTML parsing
    features['avg_word_host'] = np.mean([len(word) for word in domain.split('.')]) if domain.split('.') else 0
    features['longest_word_host'] = max(len(word) for word in domain.split('.')) if domain.split('.') else 0
    # features['random_domain'] = 0  # Placeholder, external sources needed
    # features['login_form'] = 0  # Placeholder, requires HTML parsing
    # features['nb_redirection'] = 0  # Placeholder, requires HTML parsing

    # Return as an array of features in the same order as the model's input
    return np.array([features[feature] for feature in features.keys()])

# Function to predict phishing
def predict_phishing(url):
    features = extract_features(url).reshape(1, -1)
    prediction = model.predict(features)
    prediction_probabilities = model.predict_proba(features)

    print(f"Prediction: {prediction[0]} (1: Phishing, 0: Safe)")
    print(f"Prediction Probabilities: {prediction_probabilities}")

    if prediction_probabilities[0][0] > prediction_probabilities[0][1]:  # Phishing
        print("Warning: This website is classified as phishing.")
    else:  # Safe
        print("Safe: This website is classified as legitimate.")

# Example usage
website = 'https://www.facebook.com/'
result = predict_phishing(website)

