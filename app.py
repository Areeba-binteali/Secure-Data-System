import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- Helper Paths ---
DATA_FILE = "secure_data.json"

# --- Load existing data ---
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w") as f:
        json.dump({}, f)

with open(DATA_FILE, "r") as f:
    db = json.load(f)

# --- Helper Functions ---
def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(db, f, indent=4)

from cryptography.hazmat.primitives import hashes  # ✅ Correct import

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # ✅ Correct hash object
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_data(data: str, key: bytes) -> str:
    cipher = Fernet(key)
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(data: str, key: bytes) -> str:
    cipher = Fernet(key)
    return cipher.decrypt(data.encode()).decode()

# --- Streamlit App ---
st.title("🔐 Multi-User Secure Data System")

# Session state setup
if "user" not in st.session_state:
    st.session_state.user = None
if "salt" not in st.session_state:
    st.session_state.salt = os.urandom(16)

# --- User Authentication ---
menu = ['Login', 'Register', 'Dashboard']
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Register":
    st.subheader("📝 Create New Account")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")
    
    if st.button("Register"):
        if new_user in db:
            st.error("User already exists!")
        else:
            salt = os.urandom(16)
            master_key = generate_key_from_password(new_pass, salt)
            db[new_user] = {
                "salt": salt.hex(),
                "master_key": master_key.decode(),
                "data": []
            }
            save_data()
            st.success("Account created! Please login.")

elif choice == "Login":
    st.subheader("🔑 Login")
    user = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if user in db:
            salt = bytes.fromhex(db[user]["salt"])
            entered_key = generate_key_from_password(password, salt).decode()
            if entered_key == db[user]["master_key"]:
                st.session_state.user = user
                st.session_state.salt = salt
                st.success(f"Welcome {user}!")
            else:
                st.error("Incorrect password.")
        else:
            st.error("User not found.")

elif choice == "Dashboard":
    if st.session_state.user:
        user = st.session_state.user
        user_data = db[user]["data"]
        key = generate_key_from_password(db[user]["master_key"], st.session_state.salt)

        st.subheader(f"🔐 Dashboard - {user}")
        st.write("Encrypt & store secret data securely.")

        data_to_store = st.text_area("Enter data")
        if st.button("Encrypt & Store"):
            encrypted = encrypt_data(data_to_store, key)
            db[user]["data"].append(encrypted)
            save_data()
            st.success("Data encrypted and saved!")

        st.subheader("📂 Stored Encrypted Data")
        if db[user]["data"]:
            selected_data = st.selectbox("Select encrypted data to decrypt", db[user]["data"])
            if st.button("Decrypt"):
                try:
                    decrypted = decrypt_data(selected_data, key)
                    st.success(f"Decrypted: {decrypted}")
                except:
                    st.error("Decryption failed. Invalid key or corrupted data.")
        else:
            st.info("No data saved yet.")
    else:
        st.warning("Please login to access your dashboard.")
