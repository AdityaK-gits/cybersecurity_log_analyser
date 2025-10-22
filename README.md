# Cybersecurity Log Analyzer (Streamlit UI)

This repository contains a Streamlit UI (`app.py`) that wraps `log_analyzer.py` to generate sample logs and run a security analysis.

Files:
- `log_analyzer.py` - the analyzer & generator (already present)
- `app.py` - Streamlit UI to interactively generate logs and run analysis
- `requirements.txt` - listing `streamlit` (add other deps used by `log_analyzer.py` if needed)

Run locally:
```powershell
Set-Location -Path 'C:\Users\HP\Downloads'
C:/Users/HP/AppData/Local/Programs/Python/Python311/python.exe -m pip install -r requirements.txt
C:/Users/HP/AppData/Local/Programs/Python/Python311/python.exe -m streamlit run app.py
```

Deploy to Streamlit Community Cloud:
1. Create a GitHub repo and push these files.
2. On https://share.streamlit.io, create a new app pointing at this repo and `app.py`.

Notes:
- `app.py` calls `subprocess.run(["python", "log_analyzer.py", ...])` so ensure `python` on PATH points to the same Python environment or modify `app.py` to use the absolute Python path.
