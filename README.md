# Phishing Analyzer API

![Python](https://img.shields.io/badge/python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.135.3-green)
![License](https://img.shields.io/badge/license-MIT-yellow)

Python-based API to detect phishing URLs using heuristics, domain intelligence, and automated risk scoring. Ideal for SOC L1 threat analysis and URL threat detection.

---

## Features

- Detects phishing URLs using:  
  - URL length  
  - IP-based URLs  
  - Suspicious keywords (`login`, `verify`, `secure`, `bank`)  
  - Domain age via WHOIS  
- Automated scoring system classifies URLs as **Phishing**, **Suspicious**, or **Legitimate**  
- FastAPI-based REST API with Swagger UI documentation  

---

## Technologies Used

- Python 3.x  
- FastAPI  
- Uvicorn  
- Pydantic  
- tldextract  
- python-whois  

---

## Run Instructions (Windows & Linux/Mac)

```bash
# 1. Create virtual environment
# Windows:
python -m venv venv
# Linux/Mac:
# python3 -m venv venv

# 2. Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
# source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run FastAPI server
uvicorn main:app --reload