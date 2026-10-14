# AI-Based Malicious URL Detection System

## 📌 About the Project

The **AI-Based Malicious URL Detection System** is a Machine Learning-based web application designed to identify potentially malicious URLs, including phishing links and fraudulent websites. It analyzes URL characteristics using feature extraction techniques and a Random Forest Classifier to help users recognize potential online threats.

The system aims to classify submitted URLs into three categories: **Safe, Suspicious, and Malicious**, providing risk indicators and safety recommendations to help users make informed decisions before opening unfamiliar links.

## 🎯 Objectives

* Detect potentially malicious URLs using Machine Learning.
* Extract numerical features from URL structures.
* Identify suspicious patterns commonly associated with phishing attacks.
* Display classification results through a user-friendly interface.
* Provide explanations of detected URL risk indicators.
* Promote awareness of phishing attacks and online scams.

## 🛠️ Technologies Used

* **Frontend:** HTML, CSS, JavaScript
* **Backend:** Python, Flask
* **Machine Learning:** Scikit-learn
* **Algorithm:** Random Forest Classifier
* **Data Processing:** Pandas
* **Model Storage:** Joblib
* **Version Control:** Git and GitHub

## ⚙️ How It Works

1. The user enters a URL into the web application.
2. The system validates the URL format.
3. The feature extraction module analyzes URL characteristics, such as URL length, special characters, subdomains, IP addresses, and suspicious keywords.
4. The trained Random Forest model analyzes the extracted features.
5. The system generates a risk classification.
6. The application displays the result, detected indicators, and relevant safety recommendations.

## ✨ Key Features

* URL input validation
* Numerical URL feature extraction
* Machine Learning-based classification
* Safe, Suspicious, and Malicious result categories
* Risk indicator explanations
* User-friendly cybersecurity dashboard
* Dataset preparation and model evaluation scripts

## ⚠️ Limitations

This system analyzes URL characteristics and cannot guarantee that a website is safe or malicious. HTTPS does not guarantee website legitimacy, and attackers may use compromised legitimate websites or URLs with normal-looking structures.

The model's effectiveness depends on the quality, size, diversity, and freshness of its training dataset. Predictions should be treated as risk estimates rather than definitive security verdicts.

## 🚀 Project Goal

The goal of this project is to explore how Machine Learning can support phishing detection and improve awareness of suspicious links through an accessible web-based application.

**Note:** This repository is a hackathon project and should not be considered a replacement for professional cybersecurity tools or established URL reputation services.
