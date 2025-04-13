import streamlit as st
import hashlib # securely convert the Passkey in hash format
import json  # data is stored in json
import os
import time
from cryptography.fernet import Fernet  # cryptography is encrypting and decrypting data securely where fernet manage the data types
import base64  # encode and decode the data url into same format.
import uuid
import pandas as pd

# Set page configuration
st.set_page_config(
    page_title="Secure Data Encryption System",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# File paths for persistent storage
USERS_FILE = "users.json"
DATA_FILE = "data.json"

# File handling functions
def load_file(filename, default=None):
    """Load data from JSON file with error handling"""
    try:
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return json.load(f)
        return default if default is not None else {}
    except json.JSONDecodeError:
        return default if default is not None else {}
    except Exception as e:
        st.error(f"Error loading {filename}: {str(e)}")
        return default if default is not None else {}

def save_file(filename, data):
    """Save data to JSON file with error handling"""
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        st.error(f"Error saving to {filename}: {str(e)}")
        return False

def autosave_data():
    """Save both users and data to disk"""
    save_file(USERS_FILE, st.session_state.users)
    save_file(DATA_FILE, st.session_state.stored_data)

# Initialize session state variables with persistent data
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = load_file(DATA_FILE, {})
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0
if 'users' not in st.session_state:
    st.session_state.users = load_file(USERS_FILE, {})
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'login_failed_attempts' not in st.session_state:
    st.session_state.login_failed_attempts = 0

# Add minimal CSS that works reliably in Streamlit
st.markdown("""
<style>
    .card {
        background-color: #69247C;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 20px;
        border-left: 5px solid #2E86C1;
    }
    .success-text {
        color: #69247C;
        font-weight: bold;
    }
    .warning-text {
        color: #ffc107;
        font-weight: bold;
    }
    .danger-text {
        color: #dc3545;
        font-weight: bold;
    }
    .info-text {
        color: #17a2b8;
        font-weight: bold;
    }
    .sidebar-content {
        padding: 20px 0;
    }
    .user-info {
        padding: 15px;
        background-color: #69247C;
        color: white;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 20px;
    }
    /* Change sidebar background color */
    [data-testid="stSidebar"] {
        background-color: #69247C;  /* Bootstrap blue */
        color: white;
    }
    div.stButton > button {
        background-color: #0d6efd !important;  /* Bootstrap primary blue */
        color: white !important;
        border: none !important;
    }

    div.stButton > button:hover {
        background-color: #0b5ed7 !important;
    }
    .footer {
        text-align: center;
        margin-top: 30px;
        padding-top: 10px;
        border-top: 1px solid #ddd;
        color: #6c757d;
    }
</style>
""", unsafe_allow_html=True)

# Function to hash password or passkey
def hash_string(input_string):
    return hashlib.sha256(input_string.encode()).hexdigest()

# Function to generate a key from passkey (for encryption)
def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

# Function to encrypt data
def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey, data_id):
    try:
        hashed_passkey = hash_string(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]["passkey"] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except Exception as e:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

# Function to generate a unique ID for data
def generate_data_id():
    return str(uuid.uuid4())

# Function to reset failed attempts
def reset_failed_attempts():
    st.session_state.failed_attempts = 0

# Function to change page
def change_page(page):
    st.session_state.current_page = page

# Function to register a new user
def register_user(username, email, password):
    if email in st.session_state.users:
        return False, "Email already registered"
    
    hashed_password = hash_string(password)
    
    st.session_state.users[email] = {
        "username": username,
        "password": hashed_password,
        "email": email
    }
    
    autosave_data()
    return True, "Registration successful"

# Function to authenticate a user
def login_user(email, password):
    if email not in st.session_state.users:
        return False, "Email not found"
    
    user = st.session_state.users[email]
    hashed_password = hash_string(password)
    
    if user["password"] == hashed_password:
        st.session_state.current_user = email
        st.session_state.login_failed_attempts = 0
        return True, "Login successful"
    else:
        st.session_state.login_failed_attempts += 1
        return False, "Incorrect password"

# Function to check if user is logged in
def is_authenticated():
    return st.session_state.current_user is not None

# Function to get current username
def get_current_username():
    if is_authenticated():
        return st.session_state.users[st.session_state.current_user]["username"]
    return None

# Function to logout user
def logout_user():
    st.session_state.current_user = None

# Function to get user statistics
def get_user_statistics():
    user_stats = {}
    
    for data in st.session_state.stored_data.values():
        user_email = data.get("user")
        if user_email in st.session_state.users:
            username = st.session_state.users[user_email]["username"]
            if username not in user_stats:
                user_stats[username] = 0
            user_stats[username] += 1
    
    stats_list = [{"Username": username, "Encrypted Entities": count} for username, count in user_stats.items()]
    return stats_list

# Function to display colored text
def colored_text(text, color_class):
    return f'<span class="{color_class}">{text}</span>'

# Function to display info box
def info_box(text, box_type="info"):
    icon_map = {
        "info": "ℹ️",
        "success": "✅",
        "warning": "⚠️",
        "danger": "❌"
    }
    color_class_map = {
        "info": "info-text",
        "success": "success-text",
        "warning": "warning-text",
        "danger": "danger-text"
    }
    
    icon = icon_map.get(box_type, "ℹ️")
    color_class = color_class_map.get(box_type, "info-text")
    
    st.markdown(f"""
    <div style="padding: 10px; border-radius: 5px; background-color: #f8f9fa; margin-bottom: 10px;">
        {icon} <span class="{color_class}">{text}</span>
    </div>
    """, unsafe_allow_html=True)

# Function to display card
def display_card(content, title=None):
    card_html = '<div class="card">'
    if title:
        card_html += f'<h3>{title}</h3>'
    card_html += f'{content}</div>'
    st.markdown(card_html, unsafe_allow_html=True)

# Main UI
st.markdown(f"""
    <h1 style="font-size: 2.5rem; color: #69247C; font-weight: bold; margin-bottom: 20px;">
        🛡️ Confidential Data Security Suite
    </h1>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown('<div class="sidebar-content">', unsafe_allow_html=True)
    
    if is_authenticated():
        username = get_current_username()
        st.markdown(f"""
        <div class="user-info">
            <div style="font-size:2rem ; color:#FCFEFE;">👤</div>
            <div style="font-weight: bold; color: #FCFEFE; margin-top: 10px;">Welcome</div>
            <div style="color: #FCFEFE; font-weight: bold; font-size: 1.2rem;">{username}</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("### 📌 Navigation")
    
    if is_authenticated():
        menu_items = {
            "Home": "🏠",
            "Store Data": "💾",
            "Retrieve Data": "🔍",
            "All Users Data": "📊",
            "Logout": "🚪"
        }
    else:
        menu_items = {
            "Home": "🏠",
            "Login": "🔑",
            "Register": "📝"
        }
    
    for page, icon in menu_items.items():
        button_style = "primary" if st.session_state.current_page == page else "secondary"
        if st.button(f"{icon} {page}", key=f"nav_{page}", use_container_width=True, type=button_style):
            change_page(page)
            st.rerun()
    
    st.markdown('<div style="margin-top: 50px; text-align: center;">', unsafe_allow_html=True)
    st.markdown("### 🛡️ Security Status")
    
    if is_authenticated():
        st.markdown(f'<p class="success-text">✓ Authenticated</p>', unsafe_allow_html=True)
        user_data_count = sum(1 for data in st.session_state.stored_data.values() 
                             if data.get("user") == st.session_state.current_user)
        st.metric("Your Encrypted Data", user_data_count)
    else:
        st.markdown(f'<p class="warning-text">⚠️ Not Authenticated</p>', unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# Page routing
if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    info_box("Too many failed attempts! Reauthorization required.", "warning")

if st.session_state.current_page == "Home":
    st.markdown("""
        <h2 style="font-size: 2rem; color: #123458; font-weight: bold; margin-bottom: 15px;">
            🏠 Welcome to the Secure Data System
        </h2>
    """, unsafe_allow_html=True)
    
    if is_authenticated():
        username = get_current_username()
        
        display_card(f"""
        <div style="color: white;">
        <h3>Hello, {username}! 👋</h3>
        <p>Use this app to <strong>securely store and retrieve data</strong> using unique passkeys.</p>
        </div>
        """)
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("💾 Store New Data", key="home_store", use_container_width=True, type="primary"):
                change_page("Store Data")
                st.rerun()
        with col2:
            if st.button("🔍 Retrieve Data", key="home_retrieve", use_container_width=True, type="secondary"):
                change_page("Retrieve Data")
                st.rerun()
        
        user_data_count = sum(1 for data in st.session_state.stored_data.values() 
                             if data.get("user") == st.session_state.current_user)
        
        info_box(f"You currently have {user_data_count} encrypted data entries.", "info")
        
        if user_data_count > 0:
            st.markdown('<h3 class="sub-header">📈 Your Recent Activity</h3>', unsafe_allow_html=True)
            
            user_data = [data for data_id, data in st.session_state.stored_data.items() 
                        if data.get("user") == st.session_state.current_user]
            user_data.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
            
            recent_data = user_data[:3]
            
            for i, data in enumerate(recent_data):
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data.get("timestamp", 0)))
                preview = data.get("data_preview", "Data")
                
                st.markdown(f"""
                <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 10px; border-left: 4px solid #2E86C1;">
                    <div style="color: #7F8C8D; font-size: 0.8rem;">{timestamp}</div>
                    <div style="font-weight: bold; margin: 5px 0;">{preview}</div>
                    <div style="color: #27AE60; font-size: 0.9rem;">✓ Securely Encrypted</div>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.markdown('<h3 class="sub-header">🔐 Secure Your Data</h3>', unsafe_allow_html=True)
        st.write("This application allows you to securely store and retrieve sensitive information.")
        
        info_box("Please register first if you are new to the system.", "warning")
        info_box("If you already have an account, please login to continue.")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📝 Register Now", key="home_register", use_container_width=True, type="primary"):
                change_page("Register")
                st.rerun()
        with col2:
            if st.button("🔑 Login", key="home_login", use_container_width=True, type="secondary"):
                change_page("Login")
                st.rerun()
        
        total_users = len(st.session_state.users)
        total_data_entries = len(st.session_state.stored_data)
        
        st.markdown('<h3 class="sub-header">📊 System Statistics</h3>', unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        with col1:
           st.metric("👥 Total Users", total_users)
        with col2:
            st.metric("🔒 Encrypted Entries", total_data_entries)
        
        user_stats = get_user_statistics()
        if user_stats:
            st.markdown('<h3 class="sub-header">👥 User Activity</h3>', unsafe_allow_html=True)
            st.write("Below is a breakdown of encrypted entities per user:")
            
            df = pd.DataFrame(user_stats)
            df = df.sort_values(by="Encrypted Entities", ascending=False)
            df.index = range(1, len(df) + 1)
            st.table(df)
            
            if len(df) > 1:
                st.markdown('<h3 class="sub-header">📈 User Activity Visualization</h3>', unsafe_allow_html=True)
                chart = st.bar_chart(df.set_index("Username"))
        else:
            info_box("No encrypted data has been stored yet.", "info")

elif st.session_state.current_page == "Register":
    st.markdown('<h2 class="sub-header">📝 Create an Account</h2>', unsafe_allow_html=True)
    
    if is_authenticated():
        username = get_current_username()
        info_box(f"You are already logged in as {username}!", "success")
        
        if st.button("🏠 Go to Home", key="reg_home", use_container_width=True, type="primary"):
            change_page("Home")
            st.rerun()
    else:
        display_card("""
        <div style="color: white;">            
        <h3>Join our secure data platform</h3>
        <p>Create an account to start storing your data securely.</p>
        </div>
        """)
        
        with st.container():
            col1, col2 = st.columns(2)
            with col1:
                username = st.text_input("👤 Username")
            with col2:
                email = st.text_input("📧 Email")
            
            password = st.text_input("🔒 Password", type="password")
            confirm_password = st.text_input("🔒 Confirm Password", type="password")
            
            register_clicked = st.button("📝 Register", key="register_btn", use_container_width=True, type="primary")
            
            if register_clicked:
                if not username or not email or not password or not confirm_password:
                    info_box("All fields are required!", "danger")
                elif password != confirm_password:
                    info_box("Passwords do not match!", "danger")
                else:
                    success, message = register_user(username, email, password)
                    if success:
                        info_box(f"{message}! Please login.", "success")
                        st.session_state.current_page = "Login"
                        st.rerun()
                    else:
                        info_box(message, "danger")
        
        st.markdown("---")
        st.markdown("""
        <div style="text-align: center;">
            Already have an account? <a href="#" onclick="parent.document.querySelector('button:has-text(\"🔑 Login\")').click();">Login here</a>
        </div>
        """, unsafe_allow_html=True)

elif st.session_state.current_page == "Login":
    st.markdown('<h2 class="sub-header">🔑 Login to Your Account</h2>', unsafe_allow_html=True)
    
    if is_authenticated():
        username = get_current_username()
        info_box(f"You are already logged in as {username}!", "success")
        
        if st.button("🏠 Go to Home", key="login_home", use_container_width=True, type="primary"):
            change_page("Home")
            st.rerun()
    else:
        if st.session_state.login_failed_attempts >= 3:
            if time.time() - st.session_state.last_attempt_time < 30:
                remaining_time = int(30 - (time.time() - st.session_state.last_attempt_time))
                info_box(f"Too many failed login attempts. Please wait {remaining_time} seconds before trying again.", "warning")
                st.stop()
            else:
                st.session_state.login_failed_attempts = 0
        
        display_card("""
        <div style="color: white;">            
        <h3>Welcome back!</h3>
        <p>Login to access your secure data.</p>
        </div>
        """)
        
        with st.container():
            email = st.text_input("📧 Email")
            password = st.text_input("🔒 Password", type="password")
            
            login_clicked = st.button("🔑 Login", key="login_btn", use_container_width=True, type="primary")
            
            if login_clicked:
                if not email or not password:
                    info_box("Both fields are required!", "danger")
                else:
                    success, message = login_user(email, password)
                    if success:
                        info_box(message, "success")
                        st.session_state.current_page = "Home"
                        st.rerun()
                    else:
                        info_box(message, "danger")
                        st.session_state.last_attempt_time = time.time()
        
        st.markdown("---")
        st.markdown("""
        <div style="text-align: center;">
            Don't have an account? <a href="#" onclick="parent.document.querySelector('button:has-text(\"📝 Register\")').click();">Register here</a>
        </div>
        """, unsafe_allow_html=True)

elif st.session_state.current_page == "Store Data":
    if not is_authenticated():
        st.markdown('<h2 class="sub-header">🔒 Authentication Required</h2>', unsafe_allow_html=True)
        info_box("Please login to store data.", "warning")
        info_box("If you don't have an account, please register first.", "info")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔑 Login", key="store_login", use_container_width=True, type="primary"):
                change_page("Login")
                st.rerun()
        with col2:
            if st.button("📝 Register", key="store_register", use_container_width=True, type="secondary"):
                change_page("Register")
                st.rerun()
    else:
        username = get_current_username()
        st.markdown(f'<h2 class="sub-header">📂 {username}\'s Secure Data Storage</h2>', unsafe_allow_html=True)
        st.write("Enter your data and create a secure passkey to encrypt it.")
        
        display_card("""
        <div style="color:  white;">
        <h3>Data Security</h3>
        <p>Your data will be encrypted with a strong encryption algorithm. Only you can access it with the correct Data ID and passkey.</p>
        </div>
        """)
        
        user_data = st.text_area("📄 Enter Data:")
        passkey = st.text_input("🔑 Enter Passkey:", type="password")
        confirm_passkey = st.text_input("🔑 Confirm Passkey:", type="password")

        encrypt_clicked = st.button("🔒 Encrypt & Save", key="encrypt_btn", use_container_width=True, type="primary")
            
        if encrypt_clicked:
            if user_data and passkey and confirm_passkey:
                if passkey != confirm_passkey:
                    info_box("Passkeys do not match!", "danger")
                else:
                    data_id = generate_data_id()
                    hashed_passkey = hash_string(passkey)
                    encrypted_text = encrypt_data(user_data, passkey)
                    
                    st.session_state.stored_data[data_id] = {
                        "encrypted_text": encrypted_text,
                        "passkey": hashed_passkey,
                        "user": st.session_state.current_user,
                        "username": username,
                        "timestamp": time.time(),
                        "data_preview": f"{user_data[:10]}..." if len(user_data) > 10 else user_data
                    }
                    
                    autosave_data()
                    info_box("Data stored securely!", "success")
                    
                    st.markdown('<h3 class="sub-header">🔑 Your Data ID:</h3>', unsafe_allow_html=True)
                    st.code(data_id, language="text")
                    info_box("IMPORTANT: Save this Data ID! You'll need it to retrieve your data.", "warning")
                    info_box("This ID is the only way to access your encrypted data. Store it safely.", "info")
            else:
                info_box("All fields are required!", "danger")

elif st.session_state.current_page == "Retrieve Data":
    if not is_authenticated():
        st.markdown('<h2 class="sub-header">🔒 Authentication Required</h2>', unsafe_allow_html=True)
        info_box("Please login to retrieve data.", "warning")
        info_box("If you don't have an account, please register first.", "info")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔑 Login", key="retrieve_login", use_container_width=True, type="primary"):
                change_page("Login")
                st.rerun()
        with col2:
            if st.button("📝 Register", key="retrieve_register", use_container_width=True, type="secondary"):
                change_page("Register")
                st.rerun()
    else:
        username = get_current_username()
        st.markdown(f'<h2 class="sub-header">🔍 {username}\'s Data Retrieval</h2>', unsafe_allow_html=True)
        
        attempts_remaining = 3 - st.session_state.failed_attempts
        info_box(f"Attempts remaining: {attempts_remaining}", "info")
        
        user_data_ids = [data_id for data_id, data in st.session_state.stored_data.items() 
                        if data.get("user") == st.session_state.current_user]
        
        if user_data_ids:
            st.write("You can select from your stored data or enter a Data ID manually:")
            selection_method = st.radio("Choose retrieval method:", ["Select from my data", "Enter Data ID manually"])
            
            if selection_method == "Select from my data":
                options = {}
                for data_id in user_data_ids:
                    data = st.session_state.stored_data[data_id]
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data.get("timestamp", 0)))
                    preview = data.get("data_preview", "Data")
                    options[f"{preview} (Created: {timestamp})"] = data_id
                
                selected_option = st.selectbox("Select your data:", list(options.keys()))
                data_id = options[selected_option]
            else:
                data_id = st.text_input("🔑 Enter Data ID:")
        else:
            st.write("You don't have any stored data yet. Please enter a Data ID:")
            data_id = st.text_input("🔑 Enter Data ID:")
        
        passkey = st.text_input("🔒 Enter Passkey:", type="password")

        decrypt_clicked = st.button("🔓 Decrypt", key="decrypt_btn", use_container_width=True, type="primary")
            
        if decrypt_clicked:
            if data_id and passkey:
                if data_id in st.session_state.stored_data:
                    if st.session_state.stored_data[data_id]["user"] == st.session_state.current_user:
                        encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                        decrypted_text = decrypt_data(encrypted_text, passkey, data_id)

                        if decrypted_text:
                            info_box("Decryption successful!", "success")
                            st.markdown('<h3 class="sub-header">📄 Your Decrypted Data:</h3>', unsafe_allow_html=True)
                            st.code(decrypted_text, language="text")
                        else:
                            info_box(f"Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}", "danger")
                    else:
                        info_box("This data ID does not belong to you!", "danger")
                else:
                    info_box("Data ID not found!", "danger")
                    
                if st.session_state.failed_attempts >= 3:
                    info_box("Too many failed attempts! Redirecting to Login Page.", "warning")
                    st.session_state.current_page = "Login"
                    st.rerun()
            else:
                info_box("Both fields are required!", "danger")

elif st.session_state.current_page == "All Users Data":
    if not is_authenticated():
        st.markdown('<h2 class="sub-header">🔒 Authentication Required</h2>', unsafe_allow_html=True)
        info_box("Please login to view all data.", "warning")
        info_box("If you don't have an account, please register first.", "info")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔑 Login", key="all_login", use_container_width=True, type="primary"):
                change_page("Login")
                st.rerun()
        with col2:
            if st.button("📝 Register", key="all_register", use_container_width=True, type="secondary"):
                change_page("Register")
                st.rerun()
    else:
        username = get_current_username()
        st.markdown('<h2 class="sub-header">📊 All Users Securely Stored Data</h2>', unsafe_allow_html=True)
        st.write("This page shows all encrypted data entries in the system.")
        info_box("Note: The actual content of encrypted data is only accessible to its owner with the correct Data ID and passkey.", "warning")
        
        if st.session_state.stored_data:
            data_list = []
            for data_id, data in st.session_state.stored_data.items():
                owner_username = data.get("username", "Unknown")
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data.get("timestamp", 0)))
                is_owner = data.get("user") == st.session_state.current_user
                
                data_list.append({
                    "Owner": owner_username,
                    "Date Created": timestamp,
                    "Data ID": data_id if is_owner else "🔒 Hidden",
                    "Status": "Your Data" if is_owner else "Encrypted (Access Restricted)"
                })
            
            df = pd.DataFrame(data_list)
            st.dataframe(df, use_container_width=True, height=300)
            
            st.markdown("---")
            st.markdown(f'<h3 class="sub-header">🔐 {username}\'s Secure Data</h3>', unsafe_allow_html=True)
            
            user_data_ids = [data_id for data_id, data in st.session_state.stored_data.items() 
                            if data.get("user") == st.session_state.current_user]
            
            if user_data_ids:
                options = {}
                for data_id in user_data_ids:
                    data = st.session_state.stored_data[data_id]
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data.get("timestamp", 0)))
                    preview = data.get("data_preview", "Data")
                    options[f"{preview} (Created: {timestamp})"] = data_id
                
                selected_option = st.selectbox("Select your data to decrypt:", list(options.keys()))
                selected_data_id = options[selected_option]
                
                passkey = st.text_input("🔒 Enter Passkey:", type="password")
                
                decrypt_clicked = st.button("🔓 Decrypt", key="all_decrypt_btn", use_container_width=True, type="primary")
                
                if decrypt_clicked:
                    if passkey:
                        encrypted_text = st.session_state.stored_data[selected_data_id]["encrypted_text"]
                        decrypted_text = decrypt_data(encrypted_text, passkey, selected_data_id)
                        
                        if decrypted_text:
                            info_box("Decryption successful!", "success")
                            st.markdown('<h3 class="sub-header">📄 Your Decrypted Data:</h3>', unsafe_allow_html=True)
                            st.code(decrypted_text, language="text")
                        else:
                            info_box(f"Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}", "danger")
                    else:
                        info_box("Passkey is required!", "danger")
            else:
                info_box("You don't have any stored data yet.", "info")
                if st.button("💾 Store New Data", key="all_store", use_container_width=True, type="primary"):
                    change_page("Store Data")
                    st.rerun()
        else:
            info_box("No data has been stored in the system yet.", "info")
            if st.button("💾 Be the first to store data", key="all_first_store", use_container_width=True, type="primary"):
                change_page("Store Data")
                st.rerun()

elif st.session_state.current_page == "Logout":
    username = get_current_username()
    logout_user()
    info_box(f"{username}, you have been logged out successfully.", "success")
    st.session_state.current_page = "Home"
    st.rerun()

# Footer
st.markdown("---")
st.markdown("""
<div class="footer" style="text-align: center; font-weight: bold; font-size: 0.9rem; color: #123458;">
    <div>🔒 <strong>Secure Data Encryption System</strong> | Educational Project</div>
    <div style="margin-top: 10px;">Designed with 🧠 for Data Security</div>
    <div style="margin-top: 10px; color: #69247C;"><strong>❤️Made by: Bilqees Shahid❤️</strong></div>
</div>
""", unsafe_allow_html=True)