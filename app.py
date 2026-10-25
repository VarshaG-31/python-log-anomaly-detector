import streamlit as st
import pandas as pd
from collections import Counter
from pathlib import Path
from datetime import datetime

def read_logs(filename):
    from pathlib import Path

    path = Path(filename)

    if not path.is_file():
        return []

    with path.open("r", encoding="utf-8") as file:
        return [
            line.strip()
            for line in file
            if line.strip()
        ]

# Page configuration
st.set_page_config(
    page_title="Log Anomaly Detector",
    page_icon="🔍",
    layout="wide"
)

# Dashboard heading
st.title("🔍 Python Log Anomaly Detector")
st.caption("Monitor application logs and identify unusual activity.")

st.divider()

# Available sample log files
LOG_FILES = {
    "Server Logs": "server.log",
    "Database Logs": "database.log",
    "Security Logs": "security.log",
}

st.sidebar.header("Log File Selection")

source_type = st.sidebar.radio(
    "Choose log source",
    ["Sample Logs", "Upload Your Own File"]
)

if source_type == "Sample Logs":

    selected_name = st.sidebar.selectbox(
        "Choose a sample log",
        list(LOG_FILES.keys())
    )

    selected_file = LOG_FILES[selected_name]
    logs = read_logs(selected_file)

else:

    uploaded_file = st.sidebar.file_uploader(
        "Upload a log file",
        type=["log", "txt"]
    )

    if uploaded_file is None:
        st.info("Please upload a .log or .txt file using the sidebar.")
        st.stop()

    try:
        content = uploaded_file.getvalue().decode("utf-8")
        logs = [
            line.strip()
            for line in content.splitlines()
            if line.strip()
        ]

        selected_file = uploaded_file.name

    except UnicodeDecodeError:
        st.error("Unable to read this file as UTF-8 text.")
        st.stop()

# Read logs safely
def read_logs(filename):
    path = Path(filename)

    if not path.is_file():
        return []

    with path.open("r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()]



if not logs:
    st.warning(f"No log entries found in {selected_file}.")
    st.stop()

# Count log levels
levels = Counter()

for log in logs:
    parts = log.split()

    for level in ("INFO", "WARNING", "ERROR", "CRITICAL"):
        if level in parts:
            levels[level] += 1
            break

# Count repeated error messages
error_messages = Counter()
warning_messages = Counter()

for log in logs:
    if "ERROR" in log:
        message = log.split("ERROR", 1)[1].strip()
        error_messages[message] += 1

    elif "WARNING" in log:
        message = log.split("WARNING", 1)[1].strip()
        warning_messages[message] += 1

# Security alert detection
security_alerts = [
    (message, count)
    for message, count in warning_messages.items()
    if "failed login" in message.lower() and count >= 3
]

# Summary cards
st.subheader("📊 Log Summary")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Log Entries", len(logs))
col2.metric("Errors", levels["ERROR"])
col3.metric("Warnings", levels["WARNING"])
col4.metric("Critical Events", levels["CRITICAL"])

st.divider()

# Log level chart
st.subheader("📈 Log Level Distribution")

chart_data = pd.DataFrame({
    "Log Level": ["INFO", "WARNING", "ERROR", "CRITICAL"],
    "Count": [
        levels["INFO"],
        levels["WARNING"],
        levels["ERROR"],
        levels["CRITICAL"],
    ],
})

st.bar_chart(chart_data, x="Log Level", y="Count")

# Security alerts
st.subheader("🛡️ Security Alerts")

if security_alerts:
    for message, count in security_alerts:
        st.error(
            f"Potential security issue: "
            f"{count} repeated failed login attempts — {message}"
        )
else:
    st.success("No repeated failed-login pattern detected in this sample.")

# Repeated errors
st.subheader("🔁 Most Frequent Errors")

if error_messages:
    error_data = pd.DataFrame(
        error_messages.most_common(),
        columns=["Error Message", "Occurrences"]
    )
    st.dataframe(error_data, use_container_width=True)
else:
    st.info("No ERROR entries found in this log file.")

# Full logs
with st.expander("📄 View All Log Entries"):
    st.code("\n".join(logs), language="text")

# Footer
st.divider()
st.caption(
    f"Source: {selected_file} | "
    f"Last analyzed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
)