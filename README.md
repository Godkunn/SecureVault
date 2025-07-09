# SecureVault: Your Personal Digital Fortress

## Overview

SecureVault is a robust and user-friendly web application designed to securely store your sensitive files. Leveraging strong cryptographic principles, it ensures that your data remains confidential and protected against unauthorized access and tampering. With a sleek, modern interface inspired by cyberpunk aesthetics and digital security themes, SecureVault offers a professional and engaging user experience.

## Features

* **Secure User Authentication:** User registration and login with strong password hashing (using `Werkzeug.security`).
* **Unique User Vaults:** Each user has a dedicated, isolated vault directory on the server.
* **Client-Side Key Derivation:** A unique, consistent encryption key (`pass_key`) is securely derived from the user's password for file encryption/decryption, ensuring data is tied to the user's credentials.
* **Strong File Encryption:** Files are encrypted using AES-256 in EAX mode (Authenticated Encryption with Associated Data) via the `cryptography` library, providing both confidentiality and integrity protection.
* **File Integrity Verification:** A "Verify" option allows users to check if their encrypted files have been tampered with or corrupted since encryption.
* **Secure File Uploads & Downloads:** Files are temporarily handled for encryption/decryption in a secure temporary directory, ensuring no unencrypted data persists on the server's public-facing side. Temporary download files are automatically cleaned up after serving.
* **Access Control:** Basic access control ensures users can only interact with files within their own vault.
* **Audit Logging:** Critical user actions (login, logout, upload, download, delete, integrity check) are logged for security auditing.
* **Dynamic Visuals:** An engaging "Matrix Rain" inspired background animation provides a modern, tech-themed aesthetic without being visually distracting.
* **Responsive Design:** Optimized for various screen sizes.

## Technology Stack

* **Backend:** Flask (Python Web Framework)
* **Database:** SQLite3 (for user management and basic metadata)
* **Cryptography:** Python's `cryptography` library (AES-EAX for file encryption, Scrypt for key derivation)
* **Password Hashing:** `Werkzeug.security` (for user password storage)
* **Frontend:** HTML5, CSS3 (Custom design with vibrant theme), JavaScript (for dynamic background)
* **Deployment:** Designed for local development and can be deployed with a WSGI server like Gunicorn/Waitress for production.

## Setup and Installation

### Prerequisites

* Python 3.x installed
* `pip` (Python package installer)

### Steps

1.  **Clone the Repository (or create project structure):**
    ```bash
    git clone [https://github.com/yourusername/securevault.git](https://github.com/yourusername/securevault.git)
    cd securevault
    ```
    (If you don't have a git repo, just navigate to your project directory `C:\Users\Hp\Desktop\secure_vault`)

2.  **Create a Virtual Environment (Recommended):**
    ```bash
    python -m venv venv
    ```

3.  **Activate the Virtual Environment:**
    * **Windows:**
        ```bash
        .\venv\Scripts\activate
        ```
    * **macOS/Linux:**
        ```bash
        source venv/bin/activate
        ```

4.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Initialize the Database:**
    The `app.py` script automatically calls `init_db()` on startup, which creates the `vault.db` file and the `users` table if they don't exist.

6.  **Run the Flask Application:**
    ```bash
    python app.py
    ```

7.  **Access the Application:**
    Open your web browser and navigate to `http://127.0.0.1:5000/`

## Project Structure

secure_vault/
├── app.py                   # Main Flask application
├── requirements.txt         # Python dependencies
├── README.md                # Project documentation (this file)
├── auth.py                  # User authentication functions (register, login, key derivation)
├── vault_crypto.py          # File encryption/decryption and integrity verification
├── access_control.py        # User vault path management and access checks
├── audit_log.py             # Security event logging
├── database.py              # SQLite database initialization and connection
├── vault_data/              # (Created automatically) Root directory for user vaults
│   └──


## Security Considerations

* **Secret Key:** The `app.secret_key` in `app.py` is randomly generated on startup for development (`os.urandom(24)`). **For production, this should be a fixed, strong, securely stored secret key.**
* **Key Derivation Salt:** The `STATIC_SCRYPT_SALT` in `auth.py` is currently static for simplicity. In a highly secure production environment, consider generating a unique salt for each user's password and storing it alongside their hashed password in the database. This adds another layer of defense against rainbow table attacks.
* **Database Security:** The SQLite database is a file on the server. Ensure it's not publicly accessible in a production deployment.
* **HTTPS:** For any web application dealing with sensitive data, **always use HTTPS in production** to encrypt communication between the user's browser and the server.
* **Temporary Files:** The system handles temporary files for upload/download cleanup. While measures are in place (`after_this_request`), robust error handling and monitoring are key in production to ensure no temporary files are left behind.
* **Error Handling:** The application includes basic flash messages for user feedback. Comprehensive logging and monitoring of server-side errors are essential for production.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.