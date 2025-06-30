from flask import Flask, render_template, request
import os
import requests
import PyPDF2
import time

app = Flask(__name__)


VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "your_api_key_here")

# Function to scan URL using VirusTotal API
def url_detection(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]

        # Poll for the result
        for _ in range(5):
            time.sleep(2)
            analysis_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers
            )
            if analysis_response.status_code == 200:
                data = analysis_response.json()["data"]
                if data["attributes"]["status"] == "completed":
                    stats = data["attributes"]["stats"]
                    if stats["malicious"] > 0 or stats["suspicious"] > 0:
                        return "Unsafe"
                    return "Safe"
        return "Timeout: Analysis not completed"
    return "Error scanning URL"

# Function to detect scam-like keywords in file content
def predict_fake_or_real_email_content(text):
    scam_keywords = ["password", "bank", "urgent", "verify", "account", "login", "click here"]
    if any(word in text.lower() for word in scam_keywords):
        return "Unsafe"
    return "Safe"

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/scam/', methods=['POST'])
def detect_scam():
    if 'file' not in request.files:
        return render_template("index.html", message="No file uploaded.")

    file = request.files['file']
    extracted_text = ""

    if file.filename.endswith('.pdf'):
        pdf_reader = PyPDF2.PdfReader(file)
        extracted_text = " ".join([
            page.extract_text() for page in pdf_reader.pages if page.extract_text()
        ])
    elif file.filename.endswith('.txt'):
        extracted_text = file.read().decode("utf-8")
    else:
        return render_template("index.html", message="Invalid file type. Please upload PDF or TXT files.")

    if not extracted_text.strip():
        return render_template("index.html", message="File is empty or unreadable.")

    result = predict_fake_or_real_email_content(extracted_text)
    return render_template("index.html", message=f"File Scan Result: {result}")

@app.route('/predict', methods=['POST'])
def predict_url():
    url = request.form.get('url', '').strip()

    if not url.startswith(('http://', 'https://')):
        return render_template("index.html", message="Enter a valid URL starting with http:// or https://")

    classification = url_detection(url)
    return render_template("index.html", input_url=url, predicted_class=f"URL Scan Result: {classification}")

if __name__ == '__main__':
    app.run(debug=True)
