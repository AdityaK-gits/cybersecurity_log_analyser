import streamlit as st
import subprocess
import os
import time
import sys
import io

# --- Streamlit Page Configuration ---
st.set_page_config(page_title="Cybersecurity Log Analyzer", page_icon="🛡️", layout="wide")

st.title("🛡️ Cybersecurity Log Analyzer")
st.info("A **Python-powered tool** that detects common attack patterns like **Brute Force Attacks, SQL Injections, DoS Attempts,** and more!")

# --- Configuration & State Management ---
# Use st.session_state to manage the 'log_generated' state
if 'log_file_path' not in st.session_state:
    st.session_state['log_file_path'] = "sample_logs.log" # Default to sample log

python_executable = sys.executable
temp_uploaded_log_file = "uploaded_logs.log" # File name for a user-uploaded log
report_file = "security_report.txt"
alerts_file = "alerts.json"

# --- Log Input Section ---
st.header("1. Log File Input")

uploaded_file = st.file_uploader(
    "Upload a Log File (e.g., .log, .txt, .csv)",
    type=['log', 'txt', 'csv'],
    help="Upload your own access log or security log file for analysis."
)

col1, col2 = st.columns(2)

# Handle file upload
if uploaded_file is not None:
    # Read the content of the uploaded file
    file_bytes = uploaded_file.getvalue()
    
    # Save the content to a temporary file
    with open(temp_uploaded_log_file, "wb") as f:
        f.write(file_bytes)
    
    # Update the session state to use the uploaded file
    st.session_state['log_file_path'] = temp_uploaded_log_file
    st.success(f"Log file **'{uploaded_file.name}'** uploaded successfully! Ready for analysis.")
    
    # Preview the first few lines of the uploaded file
    try:
        preview_content = file_bytes.decode('utf-8').splitlines()[:10]
        st.text_area("Preview of Uploaded Logs (First 10 Lines):", "\n".join(preview_content), height=200)
    except Exception:
        st.warning("Could not display log preview.")
        
    log_exists = True # Log is now ready

# --- Log Generation (Fallback/Sample) ---
with col1:
    st.subheader("Or, Generate Sample Logs")
    num_logs = st.slider("Number of sample logs to generate", min_value=100, max_value=5000, step=100, value=1000, key="log_slider")

    if st.button("🧾 Generate Sample Logs", use_container_width=True):
        with st.spinner("Generating logs..."):
            # Ensure the subprocess command uses the correct Python interpreter
            result = subprocess.run(
                [python_executable, "log_analyzer.py", "--generate", "--num-logs", str(num_logs)],
                capture_output=True, text=True
            )
            if result.returncode == 0 and os.path.exists(st.session_state['log_file_path']):
                st.success(f"Generated {num_logs} sample logs successfully! Ready for analysis. ✅")
                st.session_state['log_file_path'] = "sample_logs.log" # Reset path to sample
                log_exists = True
                # Preview of generated logs
                try:
                    log_preview = "\n".join(open(st.session_state['log_file_path']).read().splitlines()[:10])
                    st.text_area("Preview of Logs (First 10 Lines):", log_preview, height=200)
                except Exception as e:
                    st.warning(f"Could not preview log file: {e}")
            else:
                st.error(f"Log generation failed! Error: {result.stderr or 'Check log_analyzer.py script.'}")

# Check if a log file is available to run analysis
log_exists = uploaded_file is not None or os.path.exists("sample_logs.log")

st.markdown("---")
st.header("2. Run Analysis")

# --- Analysis Button ---
if st.button("🚨 Run Full Analysis", use_container_width=True, disabled=not log_exists):
    if not log_exists:
        st.error("Please either **Upload** a log file or **Generate Sample Logs** first.")
    else:
        current_log_file = st.session_state['log_file_path']
        st.info(f"Analyzing logs from: **{current_log_file}**")
        
        with st.spinner("Analyzing logs... This may take a moment."):
            # Pass the currently active log file path to the log_analyzer.py script
            analysis_result = subprocess.run(
                [python_executable, "log_analyzer.py", "--logs", current_log_file, "--report", report_file],
                capture_output=True, text=True
            )
            time.sleep(1) # Minor delay for UX

            if analysis_result.returncode == 0:
                st.success("✅ Analysis complete! Report generated.")

                # --- Display & Download Report ---
                if os.path.exists(report_file):
                    st.subheader("Security Report Summary")
                    report_content = open(report_file).read()
                    st.text_area("Report Preview:", report_content, height=300)

                    col_dl1, col_dl2 = st.columns(2)

                    # Download Security Report
                    with col_dl1:
                        st.download_button(
                            label="⬇️ Download Security Report",
                            data=report_content.encode('utf-8'),
                            file_name="security_report.txt",
                            mime="text/plain",
                            use_container_width=True
                        )
                    
                    # Download Alerts JSON
                    if os.path.exists(alerts_file):
                        with col_dl2:
                            with open(alerts_file, "rb") as f:
                                st.download_button(
                                    label="⬇️ Download Alerts JSON",
                                    data=f.read(),
                                    file_name="alerts.json",
                                    mime="application/json",
                                    use_container_width=True
                                )
            else:
                st.error(f"Analysis failed! Error: {analysis_result.stderr or 'Check log_analyzer.py script.'}")

st.markdown("---")
st.markdown("<p style='text-align: center; color: grey;'>Created by <strong>Aditya Kolluru</strong> | Powered by Python 🐍</p>", unsafe_allow_html=True)

