
# 🛡️ Digital Detective AI

### AI-Powered Digital Forensics and Cybersecurity Investigation Platform

Digital Detective AI is an educational cybersecurity application built with Python, Streamlit, and Groq AI.

It analyzes uploaded security logs, detects suspicious activities, identifies possible attack patterns, and generates AI-assisted forensic investigation reports.

## 🚀 Features

- Security log upload (CSV and TXT)
- Automatic log parsing
- Suspicious login detection
- Brute-force pattern detection
- Success after failed login detection
- Suspicious event keyword detection
- Risk scoring system
- Security event timeline
- Interactive cybersecurity dashboard
- AI Security Analyst chatbot
- AI-generated forensic reports
- Downloadable investigation reports
- Sample security logs for demonstration

## 🧰 Technologies

- Python
- Streamlit
- Groq API
- Pandas
- Plotly

## 📁 Project Structure

Digital-Detective-AI/
│
├── app.py
├── requirements.txt
├── README.md
└── .gitignore

## ⚙️ Installation

1. Clone the repository:

   git clone YOUR_GITHUB_REPOSITORY_URL

2. Enter the project directory:

   cd Digital-Detective-AI

3. Install dependencies:

   pip install -r requirements.txt

4. Configure your Groq API key.

For local development, create:

.streamlit/secrets.toml

Add:

GROQ_API_KEY = "your_groq_api_key"

Never upload this file to GitHub.

5. Run the application:

   streamlit run app.py

## 🔐 API Configuration

The application uses Groq's API for AI-powered analysis.

Add the following to Streamlit Community Cloud Secrets:

GROQ_API_KEY = "your_groq_api_key"

Do not hardcode API keys in app.py.

## 📊 How to Use

1. Open the application.
2. Navigate to Log Investigation.
3. Upload a CSV or TXT security log.
4. Click Analyze Uploaded Logs.
5. Open Threat Findings to review detected patterns.
6. Use AI Security Analyst to ask questions.
7. Generate and download your forensic report.

You can also load sample data to test the application.

## ⚠️ Disclaimer

This is an educational investigation assistant.

It uses heuristic detection rules and AI-generated explanations.
Its findings are not proof of malicious activity.

Always verify findings using authorized security tools and original evidence.

Use only security logs that you own or have permission to investigate.

## 👨‍💻 Project Purpose

Developed as an AI and cybersecurity university project.
