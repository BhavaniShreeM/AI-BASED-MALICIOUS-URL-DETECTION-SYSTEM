import React, { useState } from 'react';
import { Check, Copy, Download, FileCode, FolderGit2, Terminal } from 'lucide-react';

interface CodeFile {
  name: string;
  language: string;
  description: string;
  content: string;
}

export const PYTHON_PROJECT_FILES: CodeFile[] = [
  {
    name: 'app.py',
    language: 'python',
    description: 'Flask backend REST API server with URL validation and Random Forest classification endpoint',
    content: `"""
AI-Based Malicious URL Detection System
Backend Server: Python & Flask
ML Engine: Scikit-learn (Random Forest Classifier)
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import joblib
from feature_extractor import extract_url_features, validate_url

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing

# Load pre-trained Random Forest model
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')
model = None

try:
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print("✓ Random Forest model loaded successfully.")
    else:
        print("⚠ model.pkl not found. Run 'python train_model.py' first.")
except Exception as e:
    print(f"Error loading model: {e}")

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for deployment monitoring"""
    return jsonify({
        "status": "online",
        "service": "Malicious URL Detection API",
        "model_loaded": model is not None
    })

@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    """
    Accepts a URL from the user, validates it, extracts 18 features,
    and returns model prediction (SAFE, SUSPICIOUS, or MALICIOUS).
    """
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()

    if not url:
        return jsonify({"error": "URL cannot be empty."}), 400

    # Step 1: Validate URL format
    is_valid, validation_msg = validate_url(url)
    if not is_valid:
        return jsonify({"error": f"Invalid URL format: {validation_msg}"}), 422

    # Step 2: Extract lexical and structural features
    features_dict, components = extract_url_features(url)
    feature_vector = [
        features_dict['url_length'],
        features_dict['domain_length'],
        features_dict['dot_count'],
        features_dict['subdomain_count'],
        int(features_dict['has_ip_address']),
        int(features_dict['has_at_symbol']),
        int(features_dict['has_double_slash_redirect']),
        features_dict['hyphen_count'],
        int(features_dict['is_shortened']),
        features_dict['suspicious_keyword_count'],
        int(features_dict['has_https']),
        features_dict['digit_ratio'],
        features_dict['special_char_count'],
        features_dict['path_depth'],
        features_dict['query_length'],
        features_dict['entropy'],
        int(features_dict['has_port']),
        int(features_dict['is_suspicious_tld'])
    ]

    # Step 3: Run Random Forest inference
    if model is not None:
        probabilities = model.predict_proba([feature_vector])[0]
        # Classes: 0 = SAFE, 1 = SUSPICIOUS, 2 = MALICIOUS
        prob_safe = float(probabilities[0]) if len(probabilities) > 0 else 0.0
        prob_suspicious = float(probabilities[1]) if len(probabilities) > 1 else 0.0
        prob_malicious = float(probabilities[2]) if len(probabilities) > 2 else 0.0
    else:
        # Fallback heuristic calculation if model not yet trained
        prob_malicious = 0.8 if (features_dict['has_ip_address'] or features_dict['has_at_symbol']) else 0.1
        prob_suspicious = 0.6 if features_dict['is_shortened'] or features_dict['is_suspicious_tld'] else 0.2
        prob_safe = max(0.0, 1.0 - (prob_malicious + prob_suspicious))

    # Step 4: Classify verdict
    if prob_malicious >= 0.45 or features_dict['has_ip_address'] or features_dict['has_at_symbol']:
        verdict = "MALICIOUS"
        confidence = round(max(prob_malicious, 0.70) * 100, 1)
    elif prob_suspicious >= 0.35 or prob_malicious >= 0.25 or features_dict['is_shortened']:
        verdict = "SUSPICIOUS"
        confidence = round(max(prob_suspicious, 0.60) * 100, 1)
    else:
        verdict = "SAFE"
        confidence = round(prob_safe * 100, 1)

    return jsonify({
        "url": url,
        "verdict": verdict,
        "confidence": confidence,
        "probabilities": {
            "safe": round(prob_safe, 3),
            "suspicious": round(prob_suspicious, 3),
            "malicious": round(prob_malicious, 3)
        },
        "components": components,
        "features": features_dict,
        "disclaimer": "URL-based heuristics provide first-line threat screening. HTTPS indicates transport encryption, not site trustworthiness."
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting Malicious URL Detector on http://127.0.0.1:{port}")
    app.run(host='0.0.0.0', port=port, debug=True)
`,
  },
  {
    name: 'feature_extractor.py',
    language: 'python',
    description: '18 Lexical, structural, and heuristic feature extraction module with Shannon entropy and regex parsing',
    content: `"""
Feature Extraction Pipeline for URL Classification
Extracts 18 lexical and structural features from raw URLs.
"""

import re
import math
from urllib.parse import urlparse
from collections import Counter

# Known URL shorteners
SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'tiny.cc', 'shorte.st', 'cutt.ly'
}

# Suspicious keywords frequently used in phishing
PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'security', 'account',
    'banking', 'secure', 'update', 'paypal', 'appleid', 'support',
    'wallet', 'recover', 'billing', 'authenticate', 'confirm', 'passcode',
    'free-gift', 'bonus', 'claim', 'unlock', 'suspended'
]

# High-risk TLDs
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'work', 'click', 'loan', 'gq', 'cf', 'ml', 'ga',
    'tk', 'buzz', 'fit', 'surf', 'racing', 'date', 'icu'
}

IPV4_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')

def validate_url(url: str) -> tuple[bool, str]:
    """Validates basic format without opening or connecting to the site."""
    if not url or len(url.strip()) < 3:
        return False, "URL string is too short."
    if '.' not in url and ':' not in url:
        return False, "Missing top-level domain or IP structure."
    return True, "Valid"

def calculate_shannon_entropy(text: str) -> float:
    """Calculates character randomness (Shannon Entropy)."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 3)

def extract_url_features(raw_url: str) -> tuple[dict, dict]:
    """
    Parses a URL and extracts 18 numerical and boolean features.
    Returns: (features_dict, components_dict)
    """
    url = raw_url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or '').lower()
    port = parsed.port
    path = parsed.path or '/'
    query = parsed.query or ''

    # Domain anatomy
    parts = hostname.split('.')
    tld = parts[-1] if len(parts) >= 2 else ''
    subdomain_count = max(0, len(parts) - 2)

    # 1. URL Length
    url_length = len(url)

    # 2. Domain Length
    domain_length = len(hostname)

    # 3. Dot Count
    dot_count = url.count('.')

    # 4. IP Address Check
    has_ip = bool(IPV4_PATTERN.match(hostname))

    # 5. Embedded '@' symbol (Credential obfuscation)
    has_at = '@' in url

    # 6. Double slash redirect in path
    has_double_slash = '//' in url.split('://', 1)[-1]

    # 7. Hyphens in domain
    hyphen_count = hostname.count('-')

    # 8. Shortener detection
    is_shortened = hostname in SHORTENER_DOMAINS

    # 9. Suspicious keywords
    lower_url = url.lower()
    matched_kws = [kw for kw in PHISHING_KEYWORDS if kw in lower_url]
    kw_count = len(matched_kws)

    # 10. HTTPS presence
    has_https = parsed.scheme == 'https'

    # 11. Digit ratio
    digits = sum(c.isdigit() for c in url)
    digit_ratio = round(digits / max(1, url_length), 3)

    # 12. Special characters
    special_chars = sum(url.count(c) for c in ['?', '=', '&', '%', '_', '-', '~', ';', '+', '!'])

    # 13. Path Depth
    path_depth = len([p for p in path.split('/') if p])

    # 14. Query Length
    query_length = len(query)

    # 15. Shannon Entropy
    entropy = calculate_shannon_entropy(url)

    # 16. Non-standard port
    has_port = bool(port and port not in (80, 443))

    # 17. High-abuse TLD
    is_suspicious_tld = tld in SUSPICIOUS_TLDS

    features = {
        "url_length": url_length,
        "domain_length": domain_length,
        "dot_count": dot_count,
        "subdomain_count": subdomain_count,
        "has_ip_address": has_ip,
        "has_at_symbol": has_at,
        "has_double_slash_redirect": has_double_slash,
        "hyphen_count": hyphen_count,
        "is_shortened": is_shortened,
        "suspicious_keyword_count": kw_count,
        "suspicious_keywords_found": matched_kws,
        "has_https": has_https,
        "digit_ratio": digit_ratio,
        "special_char_count": special_chars,
        "path_depth": path_depth,
        "query_length": query_length,
        "entropy": entropy,
        "has_port": has_port,
        "is_suspicious_tld": is_suspicious_tld
    }

    components = {
        "protocol": parsed.scheme,
        "hostname": hostname,
        "tld": tld,
        "subdomain_count": subdomain_count,
        "path": path,
        "query": query
    }

    return features, components
`,
  },
  {
    name: 'train_model.py',
    language: 'python',
    description: 'Scikit-learn Random Forest training script with dataset loading, evaluation metrics, and model.pkl serialization',
    content: `"""
Train Random Forest Classifier for Malicious URL Detection
Uses scikit-learn ensemble learning on a labeled dataset.
"""

import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from feature_extractor import extract_url_features

def build_dataset_features(csv_path: str):
    """Loads CSV containing 'url' and 'label' (0=Safe, 1=Suspicious, 2=Malicious)."""
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} labeled URL samples.")

    X = []
    y = []

    for _, row in df.iterrows():
        url = str(row['url'])
        label = int(row['label'])
        try:
            feats, _ = extract_url_features(url)
            vec = [
                feats['url_length'],
                feats['domain_length'],
                feats['dot_count'],
                feats['subdomain_count'],
                int(feats['has_ip_address']),
                int(feats['has_at_symbol']),
                int(feats['has_double_slash_redirect']),
                feats['hyphen_count'],
                int(feats['is_shortened']),
                feats['suspicious_keyword_count'],
                int(feats['has_https']),
                feats['digit_ratio'],
                feats['special_char_count'],
                feats['path_depth'],
                feats['query_length'],
                feats['entropy'],
                int(feats['has_port']),
                int(feats['is_suspicious_tld'])
            ]
            X.append(vec)
            y.append(label)
        except Exception as e:
            continue

    return np.array(X), np.array(y)

def train_and_evaluate():
    dataset_file = 'dataset.csv'
    if not os.path.exists(dataset_file):
        print("Creating baseline dataset.csv with representative samples...")
        # Automatically generate baseline sample dataset if not present
        from dataset_generator import create_sample_csv
        create_sample_csv(dataset_file)

    print("Extracting 18 features across dataset...")
    X, y = build_dataset_features(dataset_file)

    # 80/20 Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"Training samples: {len(X_train)} | Test samples: {len(X_test)}")

    # Initialize Random Forest Classifier
    rf_model = RandomForestClassifier(
        n_estimators=100,        # Ensemble of 100 decision trees
        max_depth=12,            # Prevent overfitting
        min_samples_split=4,
        class_weight='balanced', # Balance classes
        random_state=42,
        n_jobs=-1
    )

    print("Fitting Random Forest ensemble...")
    rf_model.fit(X_train, y_train)

    # Predict on holdout test set
    y_pred = rf_model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\\n==========================================")
    print(f"Model Test Accuracy: {acc * 100:.2f}%")
    print(f"==========================================")

    target_names = ['SAFE (0)', 'SUSPICIOUS (1)', 'MALICIOUS (2)']
    print("\\nClassification Report:\\n")
    print(classification_report(y_test, y_pred, target_names=target_names))

    # Cross-validation
    cv_scores = cross_val_score(rf_model, X, y, cv=5)
    print(f"5-Fold Cross-Validation Accuracy: {cv_scores.mean() * 100:.2f}% (+/- {cv_scores.std() * 100:.2f}%)")

    # Save trained model to disk
    joblib.dump(rf_model, 'model.pkl')
    print("\\n✓ Model saved successfully to 'model.pkl'")

if __name__ == '__main__':
    train_and_evaluate()
`,
  },
  {
    name: 'requirements.txt',
    language: 'plaintext',
    description: 'Python package dependencies for Flask and Scikit-learn',
    content: `flask==3.0.2
flask-cors==4.0.0
scikit-learn==1.4.1.post1
pandas==2.2.1
numpy==1.26.4
joblib==1.3.2
gunicorn==21.2.0
`,
  },
  {
    name: 'dataset.csv',
    language: 'csv',
    description: 'Sample labeled training dataset with legitimate (0), suspicious (1), and malicious (2) URLs',
    content: `url,label
https://www.google.com/search?q=cybersecurity,0
https://github.com/explore,0
https://en.wikipedia.org/wiki/Machine_learning,0
https://stackoverflow.com/questions,0
https://www.python.org/doc/,0
https://medium.com/topic/technology,0
https://www.nature.com/articles,0
https://www.khanacademy.org/math,0
https://docs.github.com/en/get-started,0
https://developer.mozilla.org/en-US/docs/Web,0
http://bit.ly/3xY9PqL-security-notice,1
http://login-verify-account-update.buzz/portal,1
http://free-gift-crypto-claim.top/bonus/airdrop,1
http://account-verification-support.rest/auth,1
http://tinyurl.com/urgent-update-passcode,1
http://security-recovery-center.click/reset,1
http://my-wallet-sync-portal.xyz/connect,1
http://192.168.1.104/paypal.com/webscr?cmd=_login-submit,2
https://paypal.com@secure-verify-update-account.ml/login.php,2
http://apple-security-id-verification-update.xyz/support/auth?token=9382103,2
http://218.45.12.98:8080/bank/update//portal/index.php,2
http://chase-bank-verify-pin-security.gq/login.asp,2
http://secure-login-wellsfargo-update.cf/auth/submit,2
http://104.244.78.12/malware/dropper.exe,2
https://microsoft.com@windows-security-alert-call-now.tk/fix.php,2
`,
  },
  {
    name: 'README.md',
    language: 'markdown',
    description: 'Hackathon documentation and GitHub setup instructions',
    content: `# AI-Based Malicious URL Detection System

A Machine Learning web application that detects phishing, fraud, and malicious URLs using lexical and structural feature extraction and an ensemble **Random Forest Classifier**.

## Features
- **18 Extracted Features**: Lexical statistics, Shannon character entropy, IP addresses, credential confusion (@), high-risk TLDs, and suspicious keywords.
- **Trained Machine Learning Model**: Scikit-learn Random Forest Classifier with ensemble voting.
- **Explainable AI**: Breaks down exactly why a link was flagged with color-coded severity indicators.
- **RESTful Flask API**: Fast, lightweight JSON endpoints for integration into browsers or mail gateways.

## Getting Started

### 1. Clone the Repository
\`\`\`bash
git clone https://github.com/YOUR_USERNAME/malicious-url-detector.git
cd malicious-url-detector
\`\`\`

### 2. Create and Activate a Virtual Environment
\`\`\`bash
# On macOS / Linux:
python3 -m venv venv
source venv/bin/activate

# On Windows:
python -m venv venv
venv\\Scripts\\activate
\`\`\`

### 3. Install Dependencies
\`\`\`bash
pip install -r requirements.txt
\`\`\`

### 4. Train the Machine Learning Model
\`\`\`bash
python train_model.py
\`\`\`
This will extract features from \`dataset.csv\`, train the Random Forest ensemble, print the accuracy metrics, and save \`model.pkl\`.

### 5. Run the Flask Web Application
\`\`\`bash
python app.py
\`\`\`
The server will start at \`http://127.0.0.1:5000\`.

### 6. Test with cURL or Postman
\`\`\`bash
curl -X POST http://127.0.0.1:5000/api/analyze \\
  -H "Content-Type: application/json" \\
  -d '{"url": "http://192.168.1.104/paypal.com/webscr"}'
\`\`\`

## Pushing to GitHub for Your Hackathon Submission
\`\`\`bash
git init
git add .
git commit -m "feat: AI-Based Malicious URL Detection System with Random Forest"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/malicious-url-detector.git
git push -u origin main
\`\`\`
`,
  },
];

export const PythonProjectExport: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<string>('app.py');
  const [copiedFile, setCopiedFile] = useState<string | null>(null);

  const activeFile = PYTHON_PROJECT_FILES.find((f) => f.name === selectedFile) || PYTHON_PROJECT_FILES[0];

  const handleCopy = (fileName: string, content: string) => {
    navigator.clipboard.writeText(content);
    setCopiedFile(fileName);
    setTimeout(() => setCopiedFile(null), 2000);
  };

  const handleDownloadAll = () => {
    // Combine all files into a structured downloadable text bundle
    let fullBundle = `================================================================================\\n`;
    fullBundle += `AI-BASED MALICIOUS URL DETECTION SYSTEM - PYTHON PROJECT CODE REPOSITORY\\n`;
    fullBundle += `For Hackathon Submission & GitHub\\n`;
    fullBundle += `================================================================================\\n\\n`;

    PYTHON_PROJECT_FILES.forEach((f) => {
      fullBundle += `\\n### FILE: ${f.name} ###\\n`;
      fullBundle += `### Description: ${f.description} ###\\n`;
      fullBundle += `--------------------------------------------------------------------------------\\n`;
      fullBundle += f.content;
      fullBundle += `\\n\\n`;
    });

    const blob = new Blob([fullBundle], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'malicious_url_detector_python_code.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900/80 border border-slate-800">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <FolderGit2 className="w-5 h-5 text-indigo-400" />
            <h3 className="text-lg font-semibold text-white">Complete Python & Flask GitHub Codebase</h3>
          </div>
          <p className="text-sm text-slate-400">
            Copy or download all production Python source code, Scikit-learn training scripts, dataset, and requirements ready for your hackathon GitHub submission.
          </p>
        </div>
        <button
          onClick={handleDownloadAll}
          className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-sm transition-colors shrink-0"
        >
          <Download className="w-4 h-4" />
          <span>Download All Code (.txt)</span>
        </button>
      </div>

      {/* Code Viewer Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left File Navigation */}
        <div className="lg:col-span-1 space-y-2">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-2 py-1">
            Project Files
          </div>
          <div className="space-y-1">
            {PYTHON_PROJECT_FILES.map((file) => {
              const isSelected = file.name === selectedFile;
              return (
                <button
                  key={file.name}
                  onClick={() => setSelectedFile(file.name)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-left text-sm transition-colors ${
                    isSelected
                      ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/30'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-2.5 truncate">
                    <FileCode className={`w-4 h-4 shrink-0 ${isSelected ? 'text-indigo-400' : 'text-slate-500'}`} />
                    <span className="font-mono text-xs font-medium truncate">{file.name}</span>
                  </div>
                  <span className="text-[10px] uppercase font-mono text-slate-500">{file.language}</span>
                </button>
              );
            })}
          </div>

          {/* Quick Terminal Guide */}
          <div className="mt-6 p-4 rounded-lg bg-slate-900/50 border border-slate-800 text-xs text-slate-400 space-y-2">
            <div className="flex items-center gap-1.5 text-slate-300 font-medium">
              <Terminal className="w-3.5 h-3.5 text-emerald-400" />
              <span>Quick Run Commands</span>
            </div>
            <div className="bg-slate-950 p-2.5 rounded font-mono text-[11px] text-slate-300 space-y-1 overflow-x-auto">
              <div>pip install -r requirements.txt</div>
              <div>python train_model.py</div>
              <div>python app.py</div>
            </div>
          </div>
        </div>

        {/* Right Code Display */}
        <div className="lg:col-span-3 rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden flex flex-col">
          {/* File Header */}
          <div className="flex items-center justify-between px-4 py-3 bg-slate-900 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-semibold text-white">{activeFile.name}</span>
                <span className="text-xs text-slate-500">·</span>
                <span className="text-xs text-slate-400">{activeFile.description}</span>
              </div>
            </div>
            <button
              onClick={() => handleCopy(activeFile.name, activeFile.content)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
            >
              {copiedFile === activeFile.name ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Code</span>
                </>
              )}
            </button>
          </div>

          {/* Code Body */}
          <div className="p-4 bg-slate-950 font-mono text-xs text-slate-300 overflow-x-auto max-h-[580px] leading-relaxed">
            <pre>
              <code>{activeFile.content}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
