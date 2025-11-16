"""
Hospital Management Dashboard (Streamlit)
Includes Bonus Features:
 - Fernet reversible encryption (optional; cryptography required)
 - Real-time activity graphs (actions per day, by role)
 - Data retention timer (admin configurable; deletes old patient records)
 - User consent banner (stored per-user)

Notes:
 - To enable Fernet reversible anonymization: install `cryptography`
   pip install cryptography
 - Run: streamlit run hospital_app.py
"""

from datetime import datetime, timedelta
import hashlib
import sqlite3
import os
import time
import json
from contextlib import contextmanager

import streamlit as st
import pandas as pd

# Optional: cryptography for reversible encryption
try:
    from cryptography.fernet import Fernet
    HAS_FERNET = True
except Exception:
    HAS_FERNET = False

APP_TITLE = "GDPR-Aware Hospital Management Dashboard"
DB_PATH = "hospital.db"
FERNET_KEY_PATH = "fernet.key"
CONSENT_STORE = "consents.json"  # stores per-user consent persistently


# ------------------------------
# SQLITE CONNECTION (WAL + timeout)
# ------------------------------
@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # WAL + pragmatic settings
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    try:
        yield conn
    finally:
        conn.commit()
        conn.close()


# ------------------------------
# INIT DB
# ------------------------------
def init_db():
    if HAS_FERNET and not os.path.exists(FERNET_KEY_PATH):
        with open(FERNET_KEY_PATH, "wb") as f:
            f.write(Fernet.generate_key())

    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS patients (
                patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                contact TEXT,
                diagnosis TEXT,
                anonymized_name TEXT,
                anonymized_contact TEXT,
                enc_name TEXT,
                enc_contact TEXT,
                date_added TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                role TEXT,
                action TEXT,
                timestamp TEXT,
                details TEXT
            )
        """)

        # seed users if empty
        c.execute("SELECT COUNT(*) as cnt FROM users")
        if c.fetchone()["cnt"] == 0:
            users = [
                ("admin", "admin123", "admin"),
                ("doctor", "doc123", "doctor"),
                ("receptionist", "rec123", "receptionist")
            ]
            c.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", users)

        # seed sample patients if none
        c.execute("SELECT COUNT(*) as cnt FROM patients")
        if c.fetchone()["cnt"] == 0:
            now = datetime.utcnow().isoformat()
            patients = [
                ("John Smith", "555-123-4567", "Hypertension", "ANON_1001", "XXX-XXX-4567", None, None, now),
                ("Sarah Johnson", "555-987-6543", "Diabetes Type 2", "ANON_1002", "XXX-XXX-6543", None, None, now)
            ]
            c.executemany("""
                INSERT INTO patients (name, contact, diagnosis, anonymized_name, anonymized_contact, enc_name, enc_contact, date_added)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, patients)


# ------------------------------
# Utilities
# ------------------------------
def hash_value(val: str) -> str:
    return hashlib.sha256(val.encode("utf-8")).hexdigest()


def anonymize_name(index: int) -> str:
    return f"ANON_{1000 + index}"


def anonymize_contact(contact: str) -> str:
    tail = contact[-4:] if contact else "0000"
    return f"XXX-XXX-{tail}"


def get_fernet():
    if not HAS_FERNET:
        return None
    key = open(FERNET_KEY_PATH, "rb").read()
    return Fernet(key)


def load_consents():
    if not os.path.exists(CONSENT_STORE):
        return {}
    try:
        with open(CONSENT_STORE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_consents(d):
    with open(CONSENT_STORE, "w") as f:
        json.dump(d, f)


# ------------------------------
# Logging / audit
# ------------------------------
def add_log(user_id, role, action, details=""):
    ts = datetime.utcnow().isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO logs (user_id, role, action, timestamp, details) VALUES (?, ?, ?, ?, ?)",
            (user_id, role, action, ts, details)
        )


# ------------------------------
# Auth & CRUD
# ------------------------------
def authenticate(username, password):
    with get_conn() as conn:
        cur = conn.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        row = cur.fetchone()
        return dict(row) if row else None


def add_patient(name, contact, diagnosis, current_user):
    try:
        with get_conn() as conn:
            cur = conn.execute("SELECT COUNT(*) as cnt FROM patients")
            idx = cur.fetchone()["cnt"] + 1
            anon_name = anonymize_name(idx)
            anon_contact = anonymize_contact(contact)

            if HAS_FERNET:
                f = get_fernet()
                enc_name = f.encrypt(name.encode()).decode()
                enc_contact = f.encrypt(contact.encode()).decode()
            else:
                enc_name = hash_value(name)
                enc_contact = hash_value(contact)

            conn.execute("""
                INSERT INTO patients (name, contact, diagnosis, anonymized_name, anonymized_contact, enc_name, enc_contact, date_added)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, contact, diagnosis, anon_name, anon_contact, enc_name, enc_contact, datetime.utcnow().isoformat()))

        add_log(current_user["user_id"], current_user["role"], "ADD_PATIENT", f"Added {anon_name}")
        return True, "Patient added successfully."
    except Exception as e:
        return False, str(e)


def fetch_patients():
    with get_conn() as conn:
        cur = conn.execute("SELECT * FROM patients ORDER BY patient_id ASC")
        rows = [dict(r) for r in cur.fetchall()]
        return rows


def fetch_logs():
    with get_conn() as conn:
        cur = conn.execute("SELECT * FROM logs ORDER BY log_id DESC")
        rows = [dict(r) for r in cur.fetchall()]
        return rows


def decrypt_val(enc):
    if not enc:
        return ""
    if HAS_FERNET:
        try:
            f = get_fernet()
            return f.decrypt(enc.encode()).decode()
        except Exception:
            return "[decryption_failed]"
    else:
        return "[hashed - irreversible]"


# ------------------------------
# Data Retention: Cleanup old patient records
# ------------------------------
def enforce_retention(days, current_user):
    """Delete patient records older than 'days' days. Also log deletions."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    cutoff_iso = cutoff.isoformat()
    deleted_count = 0
    with get_conn() as conn:
        # find records to delete
        to_delete = conn.execute("SELECT patient_id, anonymized_name, date_added FROM patients WHERE date_added < ?", (cutoff_iso,)).fetchall()
        deleted_count = len(to_delete)
        conn.execute("DELETE FROM patients WHERE date_added < ?", (cutoff_iso,))
    add_log(current_user["user_id"], current_user["role"], "ENFORCE_RETENTION", f"Deleted {deleted_count} patients older than {days} days")
    return deleted_count


# ------------------------------
# Real-time activity graph data
# ------------------------------
def actions_per_day(days=30):
    """Return dataframe with counts of actions per day over last 'days' days."""
    logs = fetch_logs()
    if not logs:
        return pd.DataFrame({"day": [], "count": []})

    df = pd.DataFrame(logs)
    # convert timestamp to date (datetime.date objects)
    df["day"] = pd.to_datetime(df["timestamp"]).dt.date
    cutoff = datetime.utcnow().date() - timedelta(days=days - 1)
    df = df[df["day"] >= cutoff]
    counts = df.groupby("day").size().reset_index(name="count")
    # reindex to include missing days; ensure 'all_days' are datetime.date objects
    all_days = pd.date_range(end=pd.Timestamp(datetime.utcnow().date()), periods=days).date
    counts = counts.set_index("day").reindex(all_days, fill_value=0).rename_axis("day").reset_index()
    return counts


def actions_by_role(days=30):
    logs = fetch_logs()
    if not logs:
        return pd.DataFrame()
    df = pd.DataFrame(logs)
    df["day"] = pd.to_datetime(df["timestamp"]).dt.date
    cutoff = datetime.utcnow().date() - timedelta(days=days - 1)
    df = df[df["day"] >= cutoff]
    pivot = pd.pivot_table(df, index="day", columns="role", values="log_id", aggfunc="count", fill_value=0)
    # ensure all days present
    all_days = pd.date_range(end=pd.Timestamp(datetime.utcnow().date()), periods=days).date
    pivot = pivot.reindex(all_days, fill_value=0).rename_axis("day").reset_index()
    return pivot


# ------------------------------
# Streamlit App UI
# ------------------------------
st.set_page_config(page_title=APP_TITLE, layout="wide")
if "app_start" not in st.session_state:
    st.session_state["app_start"] = time.time()
if "last_sync" not in st.session_state:
    st.session_state["last_sync"] = datetime.utcnow().isoformat()

# Initialize DB
init_db()

# Load consent store
consents = load_consents()

# Sidebar - Authentication and controls
with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/commons/4/45/Hospital_icon.svg", width=100)
    st.title("Access")

    if "current_user" not in st.session_state:
        st.session_state["current_user"] = None

    if st.session_state["current_user"] is None:
        with st.form("login_form"):
            u = st.text_input("Username")
            p = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            if submitted:
                user = authenticate(u.strip(), p.strip())
                if user:
                    st.session_state["current_user"] = user
                    add_log(user["user_id"], user["role"], "LOGIN", f"{user['username']} logged in")
                    # initialize consent store for user if missing
                    if user["username"] not in consents:
                        consents[user["username"]] = {"consented": False, "consent_time": None}
                        save_consents(consents)
                    st.rerun()
                else:
                    st.error("Invalid credentials")
    else:
        user = st.session_state["current_user"]
        st.markdown(f"**User:** {user['username']}")
        st.markdown(f"**Role:** {user['role'].capitalize()}")
        if st.button("Logout"):
            add_log(user["user_id"], user["role"], "LOGOUT", f"{user['username']} logged out")
            st.session_state["current_user"] = None
            st.rerun()

    st.write("---")
    st.markdown("**System Controls**")
    if st.button("Force Sync (update timestamp)"):
        st.session_state["last_sync"] = datetime.utcnow().isoformat()
        if st.session_state["current_user"]:
            add_log(st.session_state["current_user"]["user_id"], st.session_state["current_user"]["role"], "FORCE_SYNC", "Manual sync")
        st.success("Synced")

    st.write("---")
    st.markdown("**Environment**")
    st.markdown(f"Fernet available: **{HAS_FERNET}**")
    st.markdown(f"DB file: `{DB_PATH}`")
    if HAS_FERNET:
        st.markdown(f"Fernet key file: `{FERNET_KEY_PATH}` (kept local)")

# If not logged in, show landing and stop
if st.session_state["current_user"] is None:
    st.header(APP_TITLE)
    st.markdown("""
    This demo implements the GDPR/CIA project with optional bonus features:
    - Reversible anonymization (Fernet) .
    - Real-time activity graphs.
    - Admin-controlled data retention cleanup.
    - Per-user consent banner stored persistently.
    """)
   
    st.stop()

current_user = st.session_state["current_user"]

# Consent banner (shown until user accepts)
user_consent = consents.get(current_user["username"], {"consented": False})
if not user_consent.get("consented", False):
    with st.container():
        st.warning("This system collects and processes personal data for the purposes of healthcare record management. By using this system you consent to the processing described in the privacy policy (demo).")
        cols = st.columns([1,1,6])
        if cols[0].button("Accept"):
            consents[current_user["username"]] = {"consented": True, "consent_time": datetime.utcnow().isoformat()}
            save_consents(consents)
            add_log(current_user["user_id"], current_user["role"], "CONSENT_ACCEPT", "User accepted consent banner")
            st.rerun()
        if cols[1].button("Decline"):
            add_log(current_user["user_id"], current_user["role"], "CONSENT_DECLINE", "User declined consent banner")
            st.error("You declined consent. You will be logged out.")
            st.session_state["current_user"] = None
            st.rerun()

# Top header
col1, col2 = st.columns([4,1])
with col1:
    st.title("Hospital Management Dashboard")
    st.caption("Confidentiality • Integrity • Availability")
with col2:
    st.metric("Last Sync (UTC)", st.session_state["last_sync"])
    uptime_seconds = int(time.time() - st.session_state["app_start"])
    st.metric("Uptime (s)", uptime_seconds)

# Navigation
tabs = ["Patients"]
if current_user["role"] == "receptionist":
    tabs.append("Add Patient")
if current_user["role"] == "admin":
    tabs.append("Audit Logs")
    tabs.append("Admin Controls")
tabs.append("Activity")  # graphs accessible to all (or can hide)
active_tab = st.radio("Navigate", tabs, horizontal=True)

# Admin raw toggle
show_raw = False
if current_user["role"] == "admin":
    show_raw = st.checkbox("Show raw data (admin only)", value=False)
    if show_raw:
        add_log(current_user["user_id"], current_user["role"], "TOGGLE_RAW_ON", "Admin enabled raw view")
    else:
        add_log(current_user["user_id"], current_user["role"], "TOGGLE_RAW_OFF", "Admin disabled raw view")

# Patients view
if active_tab == "Patients":
    st.subheader("Patient Records")
    patients = fetch_patients()
    if not patients:
        st.info("No patient records yet.")
    else:
        display_rows = []
        for p in patients:
            if current_user["role"] == "admin" and show_raw:
                name = p["name"] or decrypt_val(p["enc_name"])
                contact = p["contact"] or decrypt_val(p["enc_contact"])
                diag = p["diagnosis"]
            else:
                name = p["anonymized_name"] or anonymize_name(p["patient_id"])
                contact = p["anonymized_contact"] or anonymize_contact(p["contact"] or "")
                diag = "••••••" if current_user["role"] != "admin" else p["diagnosis"]

            display_rows.append({
                "Patient ID": p["patient_id"],
                "Name": name,
                "Contact": contact,
                "Diagnosis": diag,
                "Date Added (UTC)": p["date_added"]
            })

        df = pd.DataFrame(display_rows)
        st.dataframe(df, use_container_width=True)

# Add Patient view (receptionist)
if active_tab == "Add Patient" and current_user["role"] == "receptionist":
    st.subheader("Add New Patient")
    with st.form("patient_form", clear_on_submit=True):
        name = st.text_input("Full name")
        contact = st.text_input("Contact number (e.g., 555-123-4567)")
        diagnosis = st.text_input("Diagnosis")
        submitted = st.form_submit_button("Add Patient")
        if submitted:
            if not (name and contact and diagnosis):
                st.error("All fields required.")
            else:
                ok, msg = add_patient(name.strip(), contact.strip(), diagnosis.strip(), current_user)
                if ok:
                    st.success(msg)
                    # add short log for UI visibility
                    st.rerun()
                else:
                    st.error(f"Failed to add patient: {msg}")

# Audit Logs (admin)
if active_tab == "Audit Logs" and current_user["role"] == "admin":
    st.subheader("Integrity Audit Logs")
    logs = fetch_logs()
    if logs:
        df_logs = pd.DataFrame(logs)
        st.dataframe(df_logs, use_container_width=True)
        csv = df_logs.to_csv(index=False)
        st.download_button("Download logs CSV", csv, file_name=f"audit_logs_{datetime.utcnow().date()}.csv", mime="text/csv")
    else:
        st.info("No logs yet.")

# Admin Controls (retention) - admin only
if active_tab == "Admin Controls" and current_user["role"] == "admin":
    st.subheader("Admin Controls & GDPR Tools")

    st.markdown("### Data Retention (Delete records older than N days)")
    retention_days = st.number_input("Retention days (delete patients older than this)", min_value=1, max_value=3650, value=365)
    if st.button("Apply Retention Cleanup"):
        deleted = enforce_retention(int(retention_days), current_user)
        st.success(f"Deleted {deleted} patient record(s) older than {retention_days} days.")
        # log already created in enforce_retention
        st.rerun()

    st.markdown("---")
    st.markdown("### Consent Store")
    st.write("Per-user consent states (persisted):")
    st.write(load_consents())
    if st.button("Clear all consents (for testing)"):
        save_consents({})
        st.success("Cleared consent store (will prompt all users next login).")
        add_log(current_user["user_id"], current_user["role"], "CLEAR_CONSENTS", "Admin cleared consent store")

    st.markdown("---")
    st.markdown("### Fernet Key Management")
    st.write(f"Fernet available: {HAS_FERNET}")
    if HAS_FERNET:
        if st.button("Download Fernet key (keep safe)"):
            with open(FERNET_KEY_PATH, "rb") as f:
                key_bytes = f.read()
            st.download_button("Download key file", key_bytes, file_name=FERNET_KEY_PATH, mime="application/octet-stream")
        if st.button("Rotate Fernet key (WARNING: existing encrypted values become non-decryptable)"):
            # rotate key: create new key file and warn
            with open(FERNET_KEY_PATH, "wb") as f:
                f.write(Fernet.generate_key())
            st.warning("Fernet key rotated. Existing encrypted data will not decrypt with the new key.")
            add_log(current_user["user_id"], current_user["role"], "ROTATE_FERNET_KEY", "Admin rotated Fernet key")

# Activity graphs (real-time)
if active_tab == "Activity":
    st.subheader("Real-time Activity Graphs")
    days = st.slider("Days to display", 7, 60, 30)
    counts = actions_per_day(days=days)
    if not counts.empty:
        # rename columns and convert to datetimelike index for plotting
        counts = counts.rename(columns={"day": "Date", "count": "Actions"})
        counts["Date"] = pd.to_datetime(counts["Date"])  # safe conversion
        st.line_chart(data=counts.set_index("Date")["Actions"])
    else:
        st.info("No activity yet to chart.")

    st.markdown("---")
    st.markdown("### Actions by Role (stacked)")
    pivot = actions_by_role(days=days)
    if not pivot.empty:
        pivot_indexed = pivot.set_index("day")
        # convert index to datetime for plotting
        pivot_indexed.index = pd.to_datetime(pivot_indexed.index)
        st.area_chart(pivot_indexed)
    else:
        st.info("No activity yet by role.")

# Footer
st.write("---")
st.caption(f"GDPR-focused demo • Fernet reversible encryption: {HAS_FERNET}")
st.caption(f"App started: {datetime.utcfromtimestamp(st.session_state['app_start']).isoformat()} UTC • Last sync: {st.session_state['last_sync']}")
