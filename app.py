import os
import re
import json
from io import StringIO
from datetime import datetime, timedelta, timezone
from collections import Counter

import pandas as pd
import plotly.express as px
import streamlit as st
from groq import Groq


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Digital Detective AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# CUSTOM DESIGN
# ============================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background: linear-gradient(135deg, #07111f, #101b32);
    color: #f1f5f9;
}

section[data-testid="stSidebar"] {
    background: #0b1425;
    border-right: 1px solid #263650;
}

.hero {
    background: linear-gradient(120deg, #122b4c, #17244b, #241d50);
    padding: 30px;
    border-radius: 18px;
    border: 1px solid #344b72;
    margin-bottom: 25px;
}

.hero h1 {
    color: #ffffff;
    font-size: 36px;
    font-weight: 800;
}

.hero p {
    color: #c2d4f0;
    font-size: 15px;
}

.metric-card {
    background: linear-gradient(145deg, #162944, #18223a);
    padding: 20px;
    border-radius: 14px;
    border: 1px solid #304969;
    min-height: 125px;
}

.metric-label {
    color: #a9bdd8;
    font-size: 13px;
}

.metric-value {
    color: #ffffff;
    font-size: 30px;
    font-weight: 800;
    margin-top: 8px;
}

.section-title {
    color: #e2eaff;
    font-size: 21px;
    font-weight: 700;
    margin-top: 25px;
}

.stButton > button {
    background: linear-gradient(90deg, #2563eb, #7c3aed);
    color: white;
    border: none;
    border-radius: 9px;
    font-weight: 600;
}

.stButton > button:hover {
    background: linear-gradient(90deg, #3b82f6, #9333ea);
    color: white;
}

div[data-testid="stFileUploader"] {
    background: #13243b;
    border: 1px dashed #5381b8;
    padding: 15px;
    border-radius: 14px;
}

.small-note {
    color: #9fb3cc;
    font-size: 12px;
}
</style>
""", unsafe_allow_html=True)


# ============================================================
# SESSION STATE
# ============================================================

if "events" not in st.session_state:
    st.session_state.events = None

if "findings" not in st.session_state:
    st.session_state.findings = []

if "ai_report" not in st.session_state:
    st.session_state.ai_report = ""

if "chat_history" not in st.session_state:
    st.session_state.chat_history = []


# ============================================================
# GROQ CONFIGURATION
# ============================================================

MODEL_NAME = "openai/gpt-oss-120b"


def get_api_key():
    """Read API key from Streamlit Secrets or environment."""

    try:
        key = st.secrets.get("GROQ_API_KEY", "")
        if key:
            return key
    except Exception:
        pass

    return os.getenv("GROQ_API_KEY", "")


def get_groq_client():
    key = get_api_key()

    if not key:
        return None

    return Groq(api_key=key)


def ask_ai(prompt):
    """Send a prompt to Groq and return its response."""

    client = get_groq_client()

    if client is None:
        return (
            "Groq API key is not configured. "
            "Add GROQ_API_KEY in Streamlit Secrets "
            "to enable AI analysis."
        )

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are Digital Detective AI, a cybersecurity "
                        "log-analysis assistant. Analyze only the "
                        "provided evidence. Distinguish observed facts "
                        "from hypotheses. Never claim that an attack is "
                        "confirmed without sufficient evidence. "
                        "Provide clear, practical defensive advice."
                    )
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_completion_tokens=1800
        )

        return response.choices[0].message.content

    except Exception as error:
        return f"AI service error: {str(error)}"


# ============================================================
# SAMPLE SECURITY LOGS
# ============================================================

def generate_sample_logs():

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    records = []

    scenarios = [
        ("192.168.1.10", "admin", "LOGIN_SUCCESS"),
        ("192.168.1.12", "student", "LOGIN_SUCCESS"),
        ("185.220.101.5", "admin", "LOGIN_FAILED"),
        ("185.220.101.5", "admin", "LOGIN_FAILED"),
        ("185.220.101.5", "admin", "LOGIN_FAILED"),
        ("185.220.101.5", "admin", "LOGIN_FAILED"),
        ("185.220.101.5", "admin", "LOGIN_FAILED"),
        ("185.220.101.5", "admin", "LOGIN_FAILED"),
        ("103.45.22.8", "root", "LOGIN_FAILED"),
        ("103.45.22.8", "root", "LOGIN_FAILED"),
        ("103.45.22.8", "root", "LOGIN_SUCCESS"),
        ("192.168.1.20", "user1", "FILE_ACCESS"),
        ("192.168.1.20", "admin", "PRIVILEGE_CHANGE"),
        ("45.33.32.156", "unknown", "PORT_SCAN"),
        ("45.33.32.156", "unknown", "PORT_SCAN"),
        ("192.168.1.15", "student", "LOGOUT"),
    ]

    for i, item in enumerate(scenarios):
        ip, username, event = item

        records.append({
            "timestamp": now - timedelta(minutes=5 * (len(scenarios) - i)),
            "source_ip": ip,
            "username": username,
            "event": event,
            "status": (
                "failed" if "FAILED" in event else "success"
            ),
            "raw": f"{ip} {username} {event}"
        })

    return pd.DataFrame(records)


# ============================================================
# LOG PARSING
# ============================================================

def normalize_columns(df):

    df.columns = [
        str(col).strip().lower().replace(" ", "_")
        for col in df.columns
    ]

    aliases = {
        "ip": "source_ip",
        "src_ip": "source_ip",
        "client_ip": "source_ip",
        "user": "username",
        "account": "username",
        "time": "timestamp",
        "date": "timestamp",
        "action": "event",
        "activity": "event",
        "result": "status"
    }

    df = df.rename(columns=aliases)

    for col in ["timestamp", "source_ip", "username", "event", "status"]:
        if col not in df.columns:
            df[col] = "unknown"

    return df


def parse_csv(file):
    df = pd.read_csv(file)
    df = normalize_columns(df)

    df["raw"] = df.astype(str).agg(" | ".join, axis=1)

    return df[[
        "timestamp", "source_ip", "username",
        "event", "status", "raw"
    ]]


def parse_txt(file):

    text = file.getvalue().decode("utf-8", errors="replace")

    rows = []

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    for line in text.splitlines():

        if not line.strip():
            continue

        ip_match = re.search(ip_pattern, line)
        ip = ip_match.group(0) if ip_match else "unknown"

        time_match = re.search(
            r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",
            line
        )

        timestamp = time_match.group(0) if time_match else datetime.now().isoformat()

        user_match = re.search(
            r"(?:user|username|account)[=: ]+([A-Za-z0-9_.-]+)",
            line,
            re.IGNORECASE
        )

        username = user_match.group(1) if user_match else "unknown"

        upper = line.upper()

        if any(x in upper for x in ["FAIL", "DENIED", "INVALID"]):
            status = "failed"
        elif any(x in upper for x in ["SUCCESS", "ACCEPTED", "GRANTED"]):
            status = "success"
        else:
            status = "unknown"

        rows.append({
            "timestamp": timestamp,
            "source_ip": ip,
            "username": username,
            "event": line[:200],
            "status": status,
            "raw": line[:1000]
        })

    return pd.DataFrame(rows)


def prepare_dataframe(df):

    df = normalize_columns(df.copy())

    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce", utc=True
    )

    df["source_ip"] = df["source_ip"].fillna("unknown").astype(str)
    df["username"] = df["username"].fillna("unknown").astype(str)
    df["event"] = df["event"].fillna("unknown").astype(str)
    df["status"] = df["status"].fillna("unknown").astype(str)
    df["raw"] = df["raw"].fillna("").astype(str)

    return df


# ============================================================
# THREAT DETECTION ENGINE
# ============================================================

def detect_threats(df):

    findings = []

    failed = df[
        df["status"].str.contains(
            "fail|denied|invalid", case=False, na=False
        )
    ]

    # Multiple failed login attempts
    ip_counts = failed["source_ip"].value_counts()

    for ip, count in ip_counts.items():

        if ip == "unknown":
            continue

        if count >= 5:

            findings.append({
                "severity": "HIGH",
                "category": "Brute Force Suspected",
                "source_ip": ip,
                "description": (
                    f"{count} failed login events were recorded "
                    f"from {ip}."
                ),
                "recommendation": (
                    "Review authentication logs, enable MFA, "
                    "and consider rate limiting."
                ),
                "evidence_count": int(count)
            })

    # Successful login after failed attempts
    for ip in failed["source_ip"].unique():

        if ip == "unknown":
            continue

        ip_events = df[df["source_ip"] == ip].sort_values("timestamp")

        fail_seen = False

        for _, event in ip_events.iterrows():

            status = str(event["status"]).lower()

            if any(x in status for x in ["fail", "denied", "invalid"]):
                fail_seen = True

            elif fail_seen and any(
                x in status for x in ["success", "accepted", "granted"]
            ):

                findings.append({
                    "severity": "CRITICAL",
                    "category": "Success After Failed Logins",
                    "source_ip": ip,
                    "description": (
                        f"A successful login from {ip} was recorded "
                        "after earlier failed login attempts."
                    ),
                    "recommendation": (
                        "Investigate the account, verify the user, "
                        "and review surrounding events."
                    ),
                    "evidence_count": 1
                })

                break

    # Suspicious security event keywords
    suspicious_keywords = {
        "PORT_SCAN": ("MEDIUM", "Possible Port Scanning"),
        "PRIVILEGE": ("HIGH", "Privilege Change"),
        "MALWARE": ("CRITICAL", "Malware Indicator"),
        "RANSOMWARE": ("CRITICAL", "Ransomware Indicator"),
        "SQL_INJECTION": ("HIGH", "Possible SQL Injection"),
        "UNAUTHORIZED": ("HIGH", "Unauthorized Access Indicator"),
        "EXPLOIT": ("HIGH", "Possible Exploit Activity"),
        "BACKDOOR": ("CRITICAL", "Backdoor Indicator")
    }

    for _, row in df.iterrows():

        event_text = (
            str(row["event"]) + " " + str(row["raw"])
        ).upper()

        for keyword, details in suspicious_keywords.items():

            if keyword in event_text:

                severity, category = details

                findings.append({
                    "severity": severity,
                    "category": category,
                    "source_ip": row["source_ip"],
                    "description": (
                        f"Keyword '{keyword}' appeared in a log event."
                    ),
                    "recommendation": (
                        "Inspect the original event and surrounding "
                        "system activity."
                    ),
                    "evidence_count": 1
                })

                break

    return findings


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk(findings):

    weights = {
        "LOW": 5,
        "MEDIUM": 10,
        "HIGH": 20,
        "CRITICAL": 30
    }

    score = sum(
        weights.get(item["severity"], 0)
        for item in findings
    )

    score = min(score, 100)

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


# ============================================================
# AI INVESTIGATION REPORT
# ============================================================

def generate_ai_report(df, findings, score, level):

    sample = df.head(80).to_dict(orient="records")

    prompt = f"""
    Analyze this cybersecurity investigation.

    RISK SCORE: {score}/100
    RISK LEVEL: {level}

    DETECTED FINDINGS:
    {json.dumps(findings, default=str, indent=2)}

    SECURITY LOG SAMPLE:
    {json.dumps(sample, default=str, indent=2)}

    Write a professional forensic investigation report with:

    1. Executive Summary
    2. Important Observations
    3. Possible Attack Techniques
    4. Suspicious IP Addresses
    5. Risk Assessment
    6. Recommended Defensive Actions
    7. Limitations of Available Evidence

    Clearly distinguish observed evidence from assumptions.
    Do not claim an attack is confirmed without proof.
    """

    return ask_ai(prompt)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown("## 🛡️ Digital Detective")
    st.caption("AI Cybersecurity Investigation Platform")

    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "🏠 Dashboard",
            "📂 Log Investigation",
            "🚨 Threat Findings",
            "🧠 AI Security Analyst",
            "📑 Forensic Report",
            "ℹ️ About Project"
        ]
    )

    st.divider()

    st.markdown("### System Status")

    if get_api_key():
        st.success("Groq API configured")
    else:
        st.warning("AI key not configured")

    st.markdown(
        '<p class="small-note">For authorized security '
        'investigation and educational use only.</p>',
        unsafe_allow_html=True
    )


# ============================================================
# HEADER
# ============================================================

st.markdown("""
<div class="hero">
    <h1>🛡️ Digital Detective AI</h1>
    <p>
        Intelligent Digital Forensics & Cyber Threat Investigation
    </p>
    <p>
        Analyze logs • Detect suspicious activity • Investigate threats
    </p>
</div>
""", unsafe_allow_html=True)


# ============================================================
# DASHBOARD
# ============================================================

if page == "🏠 Dashboard":

    st.markdown("### 📊 Security Operations Overview")

    if st.session_state.events is None:

        st.info(
            "No investigation loaded. Open Log Investigation "
            "and upload logs or load sample data."
        )

        st.markdown("#### What this platform can do")

        c1, c2, c3 = st.columns(3)

        c1.info("🔍 Detect suspicious login patterns")
        c2.info("🤖 Generate AI investigation reports")
        c3.info("📈 Visualize security events")

    else:

        df = st.session_state.events
        findings = st.session_state.findings
        score, level = calculate_risk(findings)

        critical = sum(
            x["severity"] == "CRITICAL" for x in findings
        )

        high = sum(
            x["severity"] == "HIGH" for x in findings
        )

        c1, c2, c3, c4 = st.columns(4)

        metrics = [
            ("Total Events", len(df)),
            ("Threat Findings", len(findings)),
            ("Critical Findings", critical),
            ("Risk Score", f"{score}/100")
        ]

        for col, (label, value) in zip(
            [c1, c2, c3, c4], metrics
        ):
            col.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-label">{label}</div>
                    <div class="metric-value">{value}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("### 🎯 Overall Risk Assessment")

        st.progress(score / 100)
        st.markdown(f"**Risk Level: {level}**")

        left, right = st.columns(2)

        with left:

            st.markdown("### Event Distribution")

            event_counts = (
                df["event"].astype(str)
                .value_counts()
                .head(10)
                .reset_index()
            )

            event_counts.columns = ["Event", "Count"]

            fig = px.pie(
                event_counts,
                names="Event",
                values="Count",
                hole=0.5,
                title="Security Event Types"
            )

            fig.update_layout(template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)

        with right:

            st.markdown("### Severity Distribution")

            severity_counts = Counter(
                x["severity"] for x in findings
            )

            severity_df = pd.DataFrame(
                list(severity_counts.items()),
                columns=["Severity", "Count"]
            )

            if not severity_df.empty:

                fig = px.bar(
                    severity_df,
                    x="Severity",
                    y="Count",
                    color="Severity",
                    title="Detected Threat Severity"
                )

                fig.update_layout(template="plotly_dark")
                st.plotly_chart(fig, use_container_width=True)

            else:
                st.info("No suspicious patterns detected.")

        st.markdown("### 🕒 Investigation Timeline")

        timeline = df.dropna(subset=["timestamp"]).sort_values(
            "timestamp"
        )

        if not timeline.empty:

            fig = px.scatter(
                timeline,
                x="timestamp",
                y="source_ip",
                color="status",
                hover_data=["username", "event"],
                title="Security Event Timeline"
            )

            fig.update_layout(template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)


# ============================================================
# LOG INVESTIGATION
# ============================================================

elif page == "📂 Log Investigation":

    st.markdown("### 📂 Upload Security Logs")

    st.write(
        "Upload CSV or TXT security logs to begin your investigation."
    )

    uploaded_file = st.file_uploader(
        "Choose a security log file",
        type=["csv", "txt"]
    )

    col1, col2 = st.columns(2)

    with col1:
        use_sample = st.button(
            "🧪 Load Sample Investigation",
            use_container_width=True
        )

    with col2:
        clear_data = st.button(
            "🗑️ Clear Investigation",
            use_container_width=True
        )

    if clear_data:

        st.session_state.events = None
        st.session_state.findings = []
        st.session_state.ai_report = ""
        st.session_state.chat_history = []

        st.success("Investigation cleared.")
        st.rerun()

    if use_sample:

        st.session_state.events = prepare_dataframe(
            generate_sample_logs()
        )

        st.session_state.findings = detect_threats(
            st.session_state.events
        )

        st.session_state.ai_report = ""
        st.session_state.chat_history = []

        st.success("Sample investigation loaded!")
        st.rerun()

    if uploaded_file is not None:

        if st.button("🔍 Analyze Uploaded Logs"):

            try:

                if uploaded_file.name.lower().endswith(".csv"):
                    raw_df = parse_csv(uploaded_file)
                else:
                    raw_df = parse_txt(uploaded_file)

                if raw_df.empty:
                    st.error("The uploaded file contains no usable logs.")
                else:

                    df = prepare_dataframe(raw_df)

                    st.session_state.events = df
                    st.session_state.findings = detect_threats(df)
                    st.session_state.ai_report = ""
                    st.session_state.chat_history = []

                    st.success(
                        f"Successfully analyzed {len(df)} log events."
                    )

                    st.rerun()

            except Exception as error:
                st.error(f"Unable to process file: {error}")

    if st.session_state.events is not None:

        st.markdown("### 📋 Parsed Security Events")

        st.dataframe(
            st.session_state.events,
            use_container_width=True,
            hide_index=True
        )

        st.download_button(
            "⬇️ Download Parsed Logs",
            data=st.session_state.events.to_csv(index=False),
            file_name="parsed_security_logs.csv",
            mime="text/csv"
        )


# ============================================================
# THREAT FINDINGS
# ============================================================

elif page == "🚨 Threat Findings":

    st.markdown("### 🚨 Threat Detection Center")

    findings = st.session_state.findings

    if not findings:

        st.info(
            "No findings available. Load sample data or upload logs "
            "first. No findings does not guarantee a system is safe."
        )

    else:

        findings_df = pd.DataFrame(findings)

        st.dataframe(
            findings_df,
            use_container_width=True,
            hide_index=True
        )

        for item in findings:

            with st.expander(
                f"{item['severity']} — {item['category']}"
            ):

                st.write("**Source IP:**", item["source_ip"])
                st.write("**Evidence:**", item["description"])
                st.write(
                    "**Recommendation:**",
                    item["recommendation"]
                )

        st.download_button(
            "⬇️ Download Threat Findings",
            data=findings_df.to_csv(index=False),
            file_name="threat_findings.csv",
            mime="text/csv"
        )


# ============================================================
# AI SECURITY ANALYST
# ============================================================

elif page == "🧠 AI Security Analyst":

    st.markdown("### 🧠 Ask Your AI Security Analyst")

    if st.session_state.events is None:

        st.warning("Load an investigation before using the analyst.")

    else:

        df = st.session_state.events
        findings = st.session_state.findings

        st.write(
            "Ask questions about your uploaded security logs "
            "and detected findings."
        )

        for message in st.session_state.chat_history:

            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        question = st.chat_input(
            "Ask something about your investigation..."
        )

        if question:

            st.session_state.chat_history.append({
                "role": "user",
                "content": question
            })

            with st.chat_message("user"):
                st.markdown(question)

            context = {
                "findings": findings,
                "event_count": len(df),
                "log_sample": df.head(60).to_dict(
                    orient="records"
                )
            }

            prompt = f"""
            INVESTIGATION DATA:
            {json.dumps(context, default=str)}

            USER QUESTION:
            {question}

            Answer using the available evidence.
            Mention uncertainty where appropriate.
            Give practical defensive recommendations.
            """

            with st.chat_message("assistant"):

                with st.spinner("Investigating..."):

                    answer = ask_ai(prompt)

                    st.markdown(answer)

            st.session_state.chat_history.append({
                "role": "assistant",
                "content": answer
            })


# ============================================================
# FORENSIC REPORT
# ============================================================

elif page == "📑 Forensic Report":

    st.markdown("### 📑 Digital Forensics Report")

    if st.session_state.events is None:

        st.warning("Load security logs before generating a report.")

    else:

        df = st.session_state.events
        findings = st.session_state.findings
        score, level = calculate_risk(findings)

        st.write(f"**Total Events:** {len(df)}")
        st.write(f"**Detected Findings:** {len(findings)}")
        st.write(f"**Risk Score:** {score}/100")
        st.write(f"**Risk Level:** {level}")

        if st.button("🤖 Generate AI Forensic Report"):

            with st.spinner("Preparing forensic report..."):

                report = generate_ai_report(
                    df, findings, score, level
                )

                st.session_state.ai_report = report

        if st.session_state.ai_report:

            st.markdown("---")
            st.markdown(st.session_state.ai_report)

            report_text = f"""
DIGITAL DETECTIVE AI
DIGITAL FORENSICS INVESTIGATION REPORT

Generated: {datetime.now().isoformat()}

Total Events: {len(df)}
Detected Findings: {len(findings)}
Risk Score: {score}/100
Risk Level: {level}

THREAT FINDINGS:

{json.dumps(findings, indent=2)}

AI INVESTIGATION:

{st.session_state.ai_report}

DISCLAIMER:
This report is an automated investigative aid.
Findings require human verification.
"""

            st.download_button(
                "⬇️ Download Full Forensic Report",
                data=report_text,
                file_name="digital_forensics_report.txt",
                mime="text/plain"
            )


# ============================================================
# ABOUT PROJECT
# ============================================================

elif page == "ℹ️ About Project":

    st.markdown("### ℹ️ About Digital Detective AI")

    st.write("""
    Digital Detective AI is an educational AI-powered
    cybersecurity investigation platform.

    It combines rule-based log analysis with a large
    language model to help users understand suspicious
    security activities.

    **Main objectives:**

    - Analyze security logs.
    - Identify suspicious authentication patterns.
    - Highlight potential security incidents.
    - Create investigation timelines.
    - Generate AI-assisted forensic reports.
    - Provide defensive security recommendations.

    **Technology used:**

    - Python
    - Streamlit
    - Groq API
    - Pandas
    - Plotly

    **Important limitations:**

    - IP addresses are not automatically verified as malicious.
    - Detection rules can produce false positives.
    - A low risk score does not prove that a system is secure.
    - AI explanations must be reviewed by a human investigator.
    - This application does not perform live network monitoring.
    """)

    st.info(
        "Use only logs that you own or are authorized to investigate."
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.markdown(
    """
    <div style="text-align:center; color:#8da4c1; padding:15px;">
        🛡️ Digital Detective AI |
        AI-Powered Digital Forensics |
        Educational Project
    </div>
    """,
    unsafe_allow_html=True
)
