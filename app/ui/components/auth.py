"""
AI Capability Demo — Authentication Component
Login page with glassmorphism design + sidebar profile badge.
"""

import streamlit as st
import textwrap
import os
from dotenv import load_dotenv

load_dotenv(override=True)


def check_auth() -> bool:
    """Check if user is authenticated."""
    return st.session_state.get("authenticated", False)


def render_login_page():
    """Render the glassmorphism login page matching Reference Image 1."""
    st.markdown(textwrap.dedent("""
    <style>
        /* Center form container */
        [data-testid="stForm"] {
            background: rgba(17, 22, 56, 0.85) !important;
            backdrop-filter: blur(20px) !important;
            -webkit-backdrop-filter: blur(20px) !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            border-radius: 20px !important;
            padding: 36px 40px !important;
            max-width: 440px !important;
            margin: 0 auto !important;
            box-shadow: 0 24px 48px rgba(0, 0, 0, 0.4) !important;
        }
        
        [data-testid="stForm"] input {
            background-color: rgba(10, 14, 39, 0.8) !important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
            border-radius: 8px !important;
            color: #ffffff !important;
            padding: 10px 14px !important;
        }
        
        [data-testid="stForm"] label {
            color: #a0a0c0 !important;
            font-size: 0.85rem !important;
            font-weight: 500 !important;
        }
        
        [data-testid="stForm"] button {
            background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%) !important;
            color: white !important;
            border: none !important;
            border-radius: 8px !important;
            font-weight: 600 !important;
            font-size: 1rem !important;
            padding: 10px 20px !important;
            width: 100% !important;
            box-shadow: 0 4px 12px rgba(0, 212, 255, 0.2) !important;
            transition: all 0.3s ease !important;
        }
        
        [data-testid="stForm"] button:hover {
            transform: translateY(-1px) !important;
            box-shadow: 0 6px 18px rgba(0, 212, 255, 0.35) !important;
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 24px;
        }
        
        .login-title-top {
            font-size: 1.8rem;
            font-weight: 800;
            color: #00ff88;
            margin-top: 12px;
            margin-bottom: 4px;
            letter-spacing: -0.02em;
        }
        
        .login-subtitle-top {
            color: #a0a0c0;
            font-size: 0.78rem;
            font-weight: 600;
            letter-spacing: 0.15em;
            text-transform: uppercase;
        }
        
        .form-title {
            color: #ffffff;
            font-size: 1.4rem;
            font-weight: 700;
            text-align: center;
            margin-bottom: 4px;
        }
        
        .form-subtitle {
            color: #6b6b8d;
            font-size: 0.8rem;
            text-align: center;
            margin-bottom: 24px;
        }
        
        .login-footer {
            text-align: center;
            color: #6b6b8d;
            font-size: 0.75rem;
            margin-top: 40px;
        }
    </style>
    """), unsafe_allow_html=True)

    col_l, col_c, col_r = st.columns([1.2, 1.8, 1.2])
    with col_c:
        st.markdown('<div style="margin-top: 40px;"></div>', unsafe_allow_html=True)
        # Centered shield and titles
        st.markdown(textwrap.dedent("""
        <div class="login-header">
            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z" fill="#3b82f6" fill-opacity="0.3" stroke="#60a5fa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                <path d="M12 18V6" stroke="#60a5fa" stroke-width="2" stroke-linecap="round"/>
                <path d="M9 12H15" stroke="#60a5fa" stroke-width="2" stroke-linecap="round"/>
            </svg>
            <div class="login-title-top">CTEM &amp; DevSecOps</div>
            <div class="login-subtitle-top">AI Platform</div>
        </div>
        """), unsafe_allow_html=True)

        with st.form("login_form", clear_on_submit=False):
            st.markdown('<div class="form-title">Sign In</div>', unsafe_allow_html=True)
            st.markdown('<div class="form-subtitle">Enter your credentials to access the platform</div>', unsafe_allow_html=True)
            
            username = st.text_input("Username", placeholder="Enter username", key="login_username_input")
            password = st.text_input("Password", type="password", placeholder="Enter password", key="login_password_input")
            
            # Form submit button
            submitted = st.form_submit_button("🔑 Sign In")

            if submitted:
                admin_user = os.getenv("ADMIN_USERNAME", "admin")
                admin_pass = os.getenv("ADMIN_PASSWORD", "changeme")

                if username == admin_user and password == admin_pass:
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.session_state.user_role = "admin"
                    st.rerun()
                else:
                    st.error("Invalid credentials. Please try again.")
                    
        # Footer
        st.markdown('<div class="login-footer">© 2026 CTEM &amp; DevSecOps AI Platform</div>', unsafe_allow_html=True)


def render_profile_badge():
    """Render the profile badge in sidebar."""
    username = st.session_state.get("username", "Unknown")
    role = st.session_state.get("user_role", "analyst")
    role_badge = "🔑 Admin" if role == "admin" else "👤 Analyst"

    st.markdown(textwrap.dedent(f"""
    <div style="
        display: flex; align-items: center; gap: 12px;
        padding: 12px 16px;
        background: rgba(255,255,255,0.04);
        border-radius: 12px;
        border: 1px solid rgba(255,255,255,0.06);
        margin-bottom: 8px;
    ">
        <div style="
            width: 36px; height: 36px;
            background: linear-gradient(135deg, #00d4ff, #a855f7);
            border-radius: 10px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.1rem; font-weight: 700; color: white;
        ">{username[0].upper()}</div>
        <div>
            <div style="font-weight: 600; font-size: 0.9rem; color: #e8e8e8;">{username}</div>
            <div style="font-size: 0.7rem; color: #6b6b8d;">{role_badge}</div>
        </div>
    </div>
    """), unsafe_allow_html=True)


def render_logout_button():
    """Render logout button in sidebar."""
    if st.button("🚪 Logout", use_container_width=True, key="logout_btn"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()
