# AI-Based Malicious URL Detection System - Frontend

This folder contains the complete, standalone frontend built with **HTML5, CSS3, and Vanilla JavaScript**.

## Files Included
- `index.html`: Modern cybersecurity interface with Header, URL Scanner, Color-Coded Result Cards (Green Safe, Orange/Yellow Suspicious, Red Malicious), Risk Indicators, Safety Recommendations, Educational Feature Extraction Guide, and Disclaimer Footer.
- `style.css`: Professional dark cybersecurity theme, fully responsive on mobile and desktop devices.
- `script.js`: Handles URL input validation, clear buttons, loading spinner state, API communication with the backend (`POST /api/analyze`), and interactive test states.

---

## How to Run This Frontend Locally

You can run this frontend on your computer using any of these simple methods:

### Option 1: Using Python's Built-in Server (Recommended for Hackathon)
If you have Python installed, open your terminal or command prompt inside the `standalone_frontend` directory and run:

```bash
cd standalone_frontend
python3 -m http.server 8000
```
*(On Windows, you can type `python -m http.server 8000`)*

Then open your browser and go to:
👉 **http://localhost:8000**

---

### Option 2: Using VS Code Live Server Extension
1. Open the project folder in **Visual Studio Code**.
2. Right-click on `index.html`.
3. Click **"Open with Live Server"**.
4. The page will immediately launch in your browser.

---

### Option 3: Direct Browser File Opening
You can simply double-click the `index.html` file in your File Explorer (Windows) or Finder (Mac) to open it in Chrome, Edge, Safari, or Firefox.

---

## Connecting to the Python/Flask Backend

When your Python Flask backend is running on `http://127.0.0.1:5000`:
- The `script.js` sends requests to `/api/analyze`.
- If running separately on a different port, enable CORS in Flask:
  ```python
  from flask_cors import CORS
  app = Flask(__name__)
  CORS(app)
  ```
- Or place these frontend files directly in your Flask app folder:
  - `index.html` inside `templates/index.html`
  - `style.css` and `script.js` inside `static/`
