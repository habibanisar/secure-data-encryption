import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os
import time
from datetime import datetime, timedelta

# Constants
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds
DATA_FILE = "secure_data.json"

# Generate or load encryption key
def get_encryption_key():
    if 'encryption_key' not in st.session_state:
        key = Fernet.generate_key()
        st.session_state['encryption_key'] = key
    return st.session_state['encryption_key']

cipher = Fernet(get_encryption_key())

# Initialize session state variables
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'locked_until' not in st.session_state:
    st.session_state.locked_until = None
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

# Load data from file or initialize empty dictionary
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

stored_data = load_data()

# Function to hash passkey with salt
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)
    return f"{salt}${hashed.hex()}"

def verify_passkey(passkey, hashed_passkey):
    if not hashed_passkey:
        return False
    salt, stored_hash = hashed_passkey.split('$')
    new_hash = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000).hex()
    return new_hash == stored_hash

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Check if system is locked
def is_locked():
    if st.session_state.locked_until and datetime.now() < st.session_state.locked_until:
        remaining_time = (st.session_state.locked_until - datetime.now()).seconds
        st.error(f"🔒 System locked! Please try again in {remaining_time} seconds.")
        return True
    return False

# Navigation
if st.session_state.get('force_login', False) or not st.session_state.authenticated:
    menu = ["Login"]
else:
    menu = ["Home", "Store Data", "Retrieve Data", "Logout"]

choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    if st.session_state.authenticated:
        st.success("You are currently authenticated.")
    else:
        st.warning("Please login to access the system.")

elif choice == "Store Data":
    if not st.session_state.authenticated:
        st.warning("Please login first.")
        st.session_state.force_login = True
        st.rerun()
    
    st.subheader("📂 Store Data Securely")
    data_name = st.text_input("Enter a name for your data:")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if not data_name:
            st.error("Please enter a name for your data.")
        elif not user_data:
            st.error("Please enter data to store.")
        elif not passkey or not confirm_passkey:
            st.error("Please enter and confirm your passkey.")
        elif passkey != confirm_passkey:
            st.error("Passkeys do not match!")
        else:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[data_name] = {
                "encrypted_text": encrypted_text, 
                "passkey": hashed_passkey,
                "timestamp": datetime.now().isoformat()
            }
            save_data(stored_data)
            st.success("✅ Data stored securely!")
            st.info(f"Data reference name: {data_name}")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated:
        st.warning("Please login first.")
        st.session_state.force_login = True
        st.rerun()
    
    if is_locked():
        st.stop()
    
    st.subheader("🔍 Retrieve Your Data")
    data_name = st.selectbox("Select your data:", [""] + list(stored_data.keys()))
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if not data_name:
            st.error("Please select data to retrieve.")
        elif not passkey:
            st.error("Please enter your passkey.")
        else:
            if data_name in stored_data:
                data_entry = stored_data[data_name]
                if verify_passkey(passkey, data_entry["passkey"]):
                    decrypted_text = decrypt_data(data_entry["encrypted_text"])
                    st.success("✅ Decrypted Data:")
                    st.text_area("", decrypted_text, height=200)
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    remaining_attempts = MAX_ATTEMPTS - st.session_state.failed_attempts
                    
                    if remaining_attempts > 0:
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining_attempts}")
                    else:
                        st.session_state.locked_until = datetime.now() + timedelta(seconds=LOCKOUT_TIME)
                        st.error("🔒 Too many failed attempts! System locked for 5 minutes.")
                        st.session_state.failed_attempts = 0
                        st.rerun()
            else:
                st.error("Selected data not found.")

elif choice == "Login":
    st.subheader("🔑 Authentication Required")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")
    
    if st.button("Login"):
        # Simple authentication (in a real app, use proper authentication)
        if username and password and password == "secure123":  # Demo password
            st.session_state.authenticated = True
            st.session_state.force_login = False
            st.session_state.failed_attempts = 0
            st.session_state.locked_until = None
            st.success("✅ Login successful!")
            time.sleep(1)
            st.rerun()
        else:
            st.error("❌ Invalid credentials")

elif choice == "Logout":
    st.session_state.authenticated = False
    st.success("✅ Logged out successfully!")
    time.sleep(1)
    st.rerun()

# Display system status in sidebar
st.sidebar.markdown("---")
st.sidebar.subheader("System Status")
if st.session_state.authenticated:
    st.sidebar.success("🔓 Authenticated")
else:
    st.sidebar.error("🔒 Not Authenticated")

if st.session_state.locked_until:
    remaining = (st.session_state.locked_until - datetime.now()).seconds
    st.sidebar.warning(f"⏳ Locked for {remaining}s")
else:
    st.sidebar.info(f"Attempts: {st.session_state.failed_attempts}/{MAX_ATTEMPTS}")

st.sidebar.markdown(f"Stored items: {len(stored_data)}")