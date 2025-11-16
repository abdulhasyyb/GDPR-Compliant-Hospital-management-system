# GDPR-Compliant-Hospital-management-system
A secure hospital management dashboard designed with GDPR privacy principles, role-based access control, audit logging, and optional reversible anonymization using Fernet encryption. Built with Streamlit, Python, and SQLite.

✨ Features
🔐 Security + GDPR Compliance

Role-Based Access Control (Admin, Doctor, Receptionist).
Patient data anonymization (masking or optional reversible encryption).
Data retention policy (auto-deletes records past admin-defined threshold).
User consent banner stored per user.
Detailed audit logs for every action (timestamp, role, user activity).
Secure handling of sensitive data (PII).

📊 Operational Tools

Real-time activity analytics (actions per day, actions by role).
Dashboard UI for patient CRUD operations.
Automatic database initialization
Clean UI built using Streamlit components

📁 Project Structure
hospital_management_system/
│── hospital_app.py          # Main Streamlit application
│── hospital.db              # Auto-generated SQLite database
│── encryption_key.key       # Generated if encryption is enabled
│── requirements.txt         # Dependencies
│── README.md                # Documentation
└── .venv/                   # Optional virtual environment

🛠️ Installation & Setup
1. Create Virtual Environment (Recommended)
python -m venv .venv

2. Install Dependencies
pip install -r requirements.txt

If you don’t have it:

pip install streamlit pandas cryptography


(cryptography is optional unless encryption is enabled)

▶️ How to Run the App

Inside the project folder:

streamlit run hospital_app.py


If the browser doesn’t open automatically:

http://localhost:8501

🔑 Optional: Enable Reversible Encryption

If your code uses Fernet anonymization:

Install:

pip install cryptography

The app will automatically generate and store encryption_key.key.


pip install streamlit --upgrade

📜 GDPR Principles Implemented
GDPR Principle	Implementation
Data Minimization	Only necessary fields stored; anonymization supported
Purpose Limitation	Data processed strictly for hospital workflow
Storage Limitation	Auto-deletion via configurable retention policy
Integrity & Confidentiality (Art. 5 + Art. 32)	Encryption, audit logs, access control
Accountability (Art. 5.2)	Logged actions per user/role
Transparency (Consent)	Persistent user consent banner
