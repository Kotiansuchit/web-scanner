# WebXRay - Website Vulnerability Scanner

WebXRay is a simple cybersecurity project developed using Python Flask, HTML, and CSS.  
It scans websites for basic security issues and generates a downloadable PDF security report.



## Features

- URL Scanner
- Security Header Checker
- Open Directory Checker
- Technology Detection
- Broken Link Finder
- Risk Level Classification
- PDF Report Generation
- Clean Dashboard UI



## Technologies Used

- Python(Flask)
- HTML
- CSS




## Security Checks Performed

### Security Headers
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security

### Open Directories
- /admin
- /backup
- /uploads
- /test
- /.env

### Technology Detection
- Server Type
- CMS Detection
- Framework Detection

### Broken Link Finder
Detects inaccessible or broken links on the target website.



## Installation

Install required libraries:

```bash
pip install flask requests beautifulsoup4 reportlab builtwith
Run Project
python app.py

Open browser:

http://127.0.0.1:5000
Project Structure
WEBXRAY/
│
├── app.py
│
├── templates/
│   └── index.html
│
├── static/
│   └── style.css
│
└── README.md

##Screenshot
![image alt]([https://github.com/Kotiansuchit/web-scanner/blob/ecb5e34f409324e543065e1d6973d6abca464882/project%20classes%20ss.png](https://github.com/Kotiansuchit/web-scanner/blob/main/project%20classes%20ss.png?raw=true))
