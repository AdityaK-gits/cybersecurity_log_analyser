import streamlit as st
import subprocess
import os
import time

st.set_page_config(page_title="Cybersecurity Log Analyzer", page_icon="🛡️", layout="wide")

st.title("🛡️ Cybersecurity Log Analyzer")
st.markdown("A Python-powered tool that detects **Brute Force Attacks, SQL Injections, DoS Attempts,** and more!")

# --- Buttons and options ---
num_logs = st.slider("Number of logs to generate", min_value=100, max_value=5000, step=100, value=1000)
log_file = "sample_logs.log"
report_file = "security_report.txt"

col1, col2 = st.columns(2)

with col1:
    if st.button("🧾 Generate Sample Logs"):
        with st.spinner("Generating logs..."):
            subprocess.run(["python", "log_analyzer.py", "--generate", "--num-logs", str(num_logs)])
            st.success(f"Generated {num_logs} sample logs ✅")
            st.text_area("Preview of Logs:", open(log_file).read().splitlines()[:10], height=200)

with col2:
    if st.button("🚨 Run Full Analysis"):
        if not os.path.exists(log_file):
            st.error("Log file not found. Please generate logs first.")
        else:
            with st.spinner("Analyzing logs..."):
                subprocess.run(["python", "log_analyzer.py", "--logs", log_file, "--report", report_file])
                time.sleep(1)
                st.success("✅ Analysis complete!")

                # Show report preview
                if os.path.exists(report_file):
                    st.subheader("Security Report Summary")
                    st.text_area("Report Preview:", open(report_file).read(), height=300)

                # Provide download buttons
                if os.path.exists(report_file):
                    st.download_button(
                        label="⬇️ Download Security Report",
                        data=open(report_file, "rb"),
                        file_name="security_report.txt",
                        mime="text/plain"
                    )

                if os.path.exists("alerts.json"):
                    st.download_button(
                        label="⬇️ Download Alerts JSON",
                        data=open("alerts.json", "rb"),
                        file_name="alerts.json",
                        mime="application/json"
                    )

st.markdown("---")
st.markdown("Created by **Aditya Kolluru** | Powered by Python 🐍")
