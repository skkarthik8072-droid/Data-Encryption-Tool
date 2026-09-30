import streamlit as st
import os

from aes_crypto import (
    derive_key_from_password,
    encrypt_message,
    decrypt_message,
)

from file_crypto import encrypt_file, decrypt_file

from rsa_crypto import (
    generate_rsa_key_pair,
    encrypt_message as rsa_encrypt_message,
    decrypt_message as rsa_decrypt_message,
)


# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="Data Encryption Tool",
    page_icon="🔐",
    layout="centered",
)


# ==================================================
# PREMIUM BLUE UI
# ==================================================

st.markdown(
    """
    <style>

    /* Main background */
    .stApp {
        background: linear-gradient(
            135deg,
            #0f172a 0%,
            #172554 50%,
            #0f172a 100%
        );
    }

    /* Main title */
    .main-title {
        font-size: 40px;
        font-weight: bold;
        text-align: center;
        color: #e0f2fe;
        margin-bottom: 5px;
    }

    /* Subtitle */
    .subtitle {
        text-align: center;
        font-size: 18px;
        color: #93c5fd;
        margin-bottom: 25px;
    }

    /* Headers */
    h1, h2, h3 {
        color: #e0f2fe !important;
    }

    /* Normal text */
    p, label {
        color: #e2e8f0 !important;
    }

    /* Buttons */
    .stButton > button {
        width: 100%;
        background: linear-gradient(
            90deg,
            #2563eb,
            #06b6d4
        );
        color: white;
        border: none;
        border-radius: 10px;
        padding: 10px;
        font-weight: bold;
        transition: 0.3s;
    }

    .stButton > button:hover {
        background: linear-gradient(
            90deg,
            #06b6d4,
            #2563eb
        );
        transform: scale(1.02);
    }

    /* Download button */
    .stDownloadButton > button {
        background: #0ea5e9;
        color: white;
        border: none;
        border-radius: 10px;
        font-weight: bold;
    }

    /* Text input */
    .stTextInput input,
    .stTextArea textarea {
        background-color: #f8fafc;
        color: #0f172a;
        border-radius: 10px;
        border: 2px solid #38bdf8;
    }

    /* File uploader */
    [data-testid="stFileUploader"] {
        background: rgba(255, 255, 255, 0.08);
        border: 2px dashed #38bdf8;
        border-radius: 12px;
        padding: 10px;
    }

    /* Divider */
    hr {
        border-color: #38bdf8 !important;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ==================================================
# TITLE
# ==================================================

st.markdown(
    '<div class="main-title">🔐 Data Encryption Tool</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="subtitle">Secure Message & File Encryption</div>',
    unsafe_allow_html=True,
)

st.info(
    "AES-256-GCM + RSA-2048 | Password Protected"
)


# ==================================================
# PASSWORD
# ==================================================

st.header("🔑 Password")

password = st.text_input(
    "Enter password",
    type="password",
    placeholder="Enter a strong password",
)


# ==================================================
# AES KEY GENERATION
# ==================================================

if password:

    if "password_salt" not in st.session_state:
        st.session_state.password_salt = os.urandom(16)

    salt = st.session_state.password_salt

    try:

        key = derive_key_from_password(
            password,
            salt,
        )

        st.success(
            "AES-256 key generated from password."
        )

        with st.expander("🔑 View Derived AES-256 Key"):

            st.code(
                key.hex()
            )

    except Exception as error:

        st.error(
            f"Key generation failed: {error}"
        )

        key = None

else:

    key = None

    st.warning(
        "Enter a password to enable encryption."
    )


# ==================================================
# MESSAGE ENCRYPTION
# ==================================================

st.divider()

st.header("💬 Message Encryption")

message = st.text_area(
    "Enter your message",
    placeholder="Type a message to encrypt...",
    height=150,
)


if st.button(
    "🔐 Encrypt Message",
    use_container_width=True,
):

    if not password:

        st.warning(
            "Please enter a password first."
        )

    elif not message.strip():

        st.warning(
            "Please enter a message."
        )

    else:

        try:

            encrypted = encrypt_message(
                message,
                key,
            )

            st.success(
                "Message encrypted successfully!"
            )

            st.subheader("Encrypted Data")

            st.code(
                encrypted.hex()
            )

            st.session_state.encrypted_message = encrypted

        except Exception as error:

            st.error(
                f"Encryption failed: {error}"
            )


# ==================================================
# MESSAGE DECRYPTION
# ==================================================

if "encrypted_message" in st.session_state:

    if st.button(
        "🔓 Decrypt Message",
        use_container_width=True,
    ):

        if not password:

            st.warning(
                "Please enter the password."
            )

        else:

            try:

                decrypted = decrypt_message(
                    st.session_state.encrypted_message,
                    key,
                )

                st.success(
                    "Message decrypted successfully!"
                )

                st.text_area(
                    "Decrypted Message",
                    value=decrypted,
                    height=100,
                )

            except Exception:

                st.error(
                    "Decryption failed. Check your password."
                )


# ==================================================
# FILE ENCRYPTION
# ==================================================

st.divider()

st.header("📁 File Encryption")

st.caption(
    "Encrypt TXT, PDF, PNG, JPG and JPEG files"
)

uploaded_file = st.file_uploader(
    "Choose a file",
    type=[
        "txt",
        "pdf",
        "png",
        "jpg",
        "jpeg",
    ],
)


if uploaded_file is not None:

    st.write(
        f"**Selected file:** `{uploaded_file.name}`"
    )

    file_data = uploaded_file.getvalue()

    st.write(
        f"**File size:** {len(file_data):,} bytes"
    )

    if st.button(
        "🔐 Encrypt File",
        use_container_width=True,
    ):

        if not password:

            st.warning(
                "Please enter a password first."
            )

        else:

            try:

                encrypted_file = encrypt_file(
                    file_data,
                    password,
                )

                st.success(
                    "File encrypted successfully!"
                )

                st.download_button(
                    label="⬇️ Download Encrypted File",
                    data=encrypted_file,
                    file_name=uploaded_file.name + ".enc",
                    mime="application/octet-stream",
                    use_container_width=True,
                )

            except Exception as error:

                st.error(
                    f"File encryption failed: {error}"
                )


# ==================================================
# FILE DECRYPTION
# ==================================================

st.divider()

st.header("🔓 File Decryption")

st.caption(
    "Decrypt password-protected .enc files"
)

encrypted_upload = st.file_uploader(
    "Upload an encrypted .enc file",
    type=["enc"],
)


if encrypted_upload is not None:

    encrypted_data = encrypted_upload.getvalue()

    st.write(
        f"**Encrypted file size:** "
        f"{len(encrypted_data):,} bytes"
    )

    if st.button(
        "🔓 Decrypt File",
        use_container_width=True,
    ):

        if not password:

            st.warning(
                "Please enter the password."
            )

        else:

            try:

                decrypted_file = decrypt_file(
                    encrypted_data,
                    password,
                )

                original_name = encrypted_upload.name

                if original_name.endswith(".enc"):
                    original_name = original_name[:-4]

                st.success(
                    "File decrypted successfully!"
                )

                st.download_button(
                    label="⬇️ Download Decrypted File",
                    data=decrypted_file,
                    file_name="decrypted_" + original_name,
                    mime="application/octet-stream",
                    use_container_width=True,
                )

            except Exception:

                st.error(
                    "File decryption failed. Check your password."
                )


# ==================================================
# RSA ENCRYPTION
# ==================================================

st.divider()

st.header("🔐 RSA-2048 Message Encryption")

st.caption(
    "RSA encryption for short messages"
)


if "rsa_private_key" not in st.session_state:

    private_key, public_key = generate_rsa_key_pair()

    st.session_state.rsa_private_key = private_key
    st.session_state.rsa_public_key = public_key


rsa_message = st.text_area(
    "Enter a short message for RSA encryption",
    placeholder="Type a short message...",
    height=120,
)


if st.button(
    "🔐 RSA Encrypt Message",
    use_container_width=True,
):

    if not rsa_message.strip():

        st.warning(
            "Please enter a message."
        )

    else:

        try:

            rsa_encrypted = rsa_encrypt_message(
                rsa_message,
                st.session_state.rsa_public_key,
            )

            st.success(
                "RSA message encrypted successfully!"
            )

            st.subheader(
                "RSA Encrypted Data"
            )

            st.code(
                rsa_encrypted.hex()
            )

            st.session_state.rsa_encrypted_message = (
                rsa_encrypted
            )

        except Exception as error:

            st.error(
                f"RSA encryption failed: {error}"
            )


# ==================================================
# RSA DECRYPTION
# ==================================================

if "rsa_encrypted_message" in st.session_state:

    if st.button(
        "🔓 RSA Decrypt Message",
        use_container_width=True,
    ):

        try:

            rsa_decrypted = rsa_decrypt_message(
                st.session_state.rsa_encrypted_message,
                st.session_state.rsa_private_key,
            )

            st.success(
                "RSA message decrypted successfully!"
            )

            st.text_area(
                "RSA Decrypted Message",
                value=rsa_decrypted,
                height=100,
            )

        except Exception as error:

            st.error(
                f"RSA decryption failed: {error}"
            )


# ==================================================
# DEVELOPER DETAILS
# ==================================================

st.divider()

st.header("👨‍💻 Developer Details")

st.write("**Name:** S. Karthik")

st.write(
    "**Course:** Computer Science Engineering"
)

st.write(
    "**Specialization:** Cyber Security"
)

st.write(
    "**College:** EASA College of Engineering and Technology"
)

st.write(
    "**Technologies:** Python, Streamlit, AES-256-GCM, RSA-2048"
)

st.write(
    "**Project:** Data Encryption Tool"
)


# ==================================================
# FOOTER
# ==================================================

st.divider()

st.caption(
    "🔐 Data Encryption Tool | "
    "AES-256-GCM + RSA-2048"
)