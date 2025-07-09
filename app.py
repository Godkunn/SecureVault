import os, shutil, logging
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, abort, after_this_request
from functools import wraps
from datetime import datetime
from mimetypes import guess_type

from auth import register_user, login_user
from vault_crypto import encrypt_file, decrypt_file, verify_file_integrity
from access_control import get_user_vault_path, create_vault_folder_for_user, check_access
from audit_log import log_event
from database import init_db

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config.update(
    VAULT_ROOT_DIR='vault_data',
    DB_FILE='vault.db',
    TEMP_UPLOAD_DIR='temp_uploads'
)

logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

for _dir in [app.config['VAULT_ROOT_DIR'], app.config['TEMP_UPLOAD_DIR']]:
    os.makedirs(_dir, exist_ok=True)
    logging.info(f"Directory ensured: {_dir}")

init_db(app.config['DB_FILE'])
logging.info("Database schema checked/created successfully.")

def get_current_user_from_session():
    """Retrieves user data from session."""
    user_id = session.get('user_id')
    username = session.get('username')
    pass_key = session.get('pass_key') # encryption key

    if user_id and username and pass_key:
        return {'id': user_id, 'username': username, 'pass_key': pass_key}
    return None

def login_required(f):
    """Decorator to ensure user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not get_current_user_from_session():
            flash("Please log in to access this page.", 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def vault_access_required(operation_type='read'):
    """
    Decorator to ensure user has general vault access (i.e., is logged in).
    Specific file-level access checks are done within routes.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user_from_session()
            if not user:
                flash("Authentication required for vault access.", 'warning')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    """Redirects logged-in users to dashboard, otherwise shows login page."""
    user = get_current_user_from_session()
    if user:
        return redirect(url_for('dashboard'))
    return render_template('login.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if get_current_user_from_session():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        user_info = login_user(username, password) # user_info contains id, username, pass_key
        if user_info:
            session.update(user_id=user_info['id'], username=user_info['username'], pass_key=user_info['pass_key'])
            flash(f"Welcome, {username}!", 'success')
            log_event(username, "Logged in via web")
            create_vault_folder_for_user(username, app.config['VAULT_ROOT_DIR']) # 3nsure vault folder exists
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Invalid username or password.", 'danger')
            log_event(username, "Failed web login attempt", success=False)
    return render_template('login.html', user=None)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if get_current_user_from_session():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        if not username or not password:
            flash("Username and password cannot be empty.", 'danger')
            return render_template('register.html', user=None)
        
        # password strength check
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", 'danger')
            return render_template('register.html', user=None)

        if register_user(username, password):
            flash("Registration successful! Please log in.", 'success')
            log_event(username, "Registered new account via web")
            return redirect(url_for('login'))
        else:
            flash("Registration failed. Username might already exist or an error occurred.", 'danger')
            log_event(username, "Failed web registration", success=False)
    return render_template('register.html', user=None)

@app.route('/logout')
@login_required
def logout():
    """Logs out the current user."""
    user = get_current_user_from_session()
    if user:
        log_event(user['username'], "Logged out via web")
    session.clear()
    flash("You have been logged out.", 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Displays the user's vault dashboard."""
    user = get_current_user_from_session()
    user_vault_path = get_user_vault_path(user['username'], app.config['VAULT_ROOT_DIR'])
    
    files_in_vault = []
    if os.path.exists(user_vault_path):
        # filter for .enc file
        files_in_vault = sorted([item for item in os.listdir(user_vault_path) if item.endswith(".enc")])
    
    return render_template('dashboard.html', files=files_in_vault, user=user)

@app.route('/upload', methods=['POST'])
@login_required
@vault_access_required(operation_type='write')
def upload_file():
    """Handles file upload and encryption."""
    user = get_current_user_from_session()
    file = request.files.get('file')

    if not file or file.filename == '':
        flash("No file selected for upload.", 'danger')
        return redirect(url_for('dashboard'))

    original_filename = file.filename
    # Creatingg a unique temporary filename to avoid conflicts and simplify cleanup
    temp_filepath = os.path.join(app.config['TEMP_UPLOAD_DIR'], f"{datetime.now().timestamp()}_{os.path.basename(original_filename)}")
    
    try:
        file.save(temp_filepath)
        user_vault_path = get_user_vault_path(user['username'], app.config['VAULT_ROOT_DIR'])
        
        # Ensuring the user's vault directory exists before encryption
        os.makedirs(user_vault_path, exist_ok=True)

        encrypted_filename = original_filename + ".enc"
        dest_path = os.path.join(user_vault_path, encrypted_filename)

        if check_access(user['username'], dest_path, 'write'):
            encrypt_file(temp_filepath, dest_path, user['pass_key'])
            flash(f"File '{original_filename}' uploaded and encrypted successfully!", 'success')
            log_event(user['username'], f"Web uploaded & encrypted {original_filename}")
        else:
            flash("Access denied to upload file.", 'danger')
            log_event(user['username'], f"Web access denied for upload of {original_filename}", success=False)
    except Exception as e:
        flash(f"Error processing file: {e}", 'danger')
        log_event(user['username'], f"Failed web upload of {original_filename}: {e}", success=False)
    finally:
        # temporary file removed
        if os.path.exists(temp_filepath):
            try:
                os.remove(temp_filepath)
                logging.info(f"Cleaned up temp upload file: {temp_filepath}")
            except Exception as e:
                logging.error(f"Error cleaning up temp upload file {temp_filepath}: {e}")
    return redirect(url_for('dashboard'))

@app.route('/download/<filename>', methods=['GET'])
@login_required
@vault_access_required(operation_type='read')
def download_file(filename):
    """Handles file download by decrypting it to a temporary location."""
    user = get_current_user_from_session()
    user_vault_path = get_user_vault_path(user['username'], app.config['VAULT_ROOT_DIR'])
    encrypted_file_path = os.path.join(user_vault_path, filename)

    if not os.path.isfile(encrypted_file_path):
        flash("File not found in your vault.", 'danger')
        log_event(user['username'], f"Attempted download of non-existent file {filename}", success=False)
        return redirect(url_for('dashboard'))
    
    if check_access(user['username'], encrypted_file_path, 'read'):
        temp_download_path = None
        try:
            original_filename = filename.replace(".enc", "") # original filename
            temp_download_filename = f"{datetime.now().timestamp()}_{os.path.basename(original_filename)}"
            temp_download_path = os.path.join(app.config['TEMP_UPLOAD_DIR'], temp_download_filename)
            
            # Decrypt content into memory and write to temp file
            decrypted_bytes = decrypt_file(encrypted_file_path, user['pass_key'])
            with open(temp_download_path, 'wb') as f:
                f.write(decrypted_bytes)
            
            log_event(user['username'], f"Web downloaded & decrypted {filename}")
            
            @after_this_request
            def remove_temp_file(response):
                """Callback to remove temporary file after response is sent."""
                if os.path.exists(temp_download_path):
                    try:
                        os.remove(temp_download_path)
                        logging.info(f"Cleaned up temp download file: {temp_download_path}")
                    except Exception as e:
                        # Log error
                        logging.error(f"Error cleaning up temp download file {temp_download_path}: {e}")
                return response
            
            return send_from_directory(app.config['TEMP_UPLOAD_DIR'], temp_download_filename, as_attachment=True, download_name=original_filename)
            
        except ValueError as ve: 
            flash(f"Integrity check failed during decryption for download: {ve}. File might be tampered with or key is wrong!", 'danger')
            log_event(user['username'], f"Integrity check failed for {filename} during web download: {ve}", success=False)
        except Exception as e:
            flash(f"Error downloading file: {e}", 'danger')
            log_event(user['username'], f"Failed web download of {filename}: {e}", success=False)
    else:
        flash("Access denied to download file.", 'danger')
        log_event(user['username'], f"Web access denied for download of {filename}", success=False)
    return redirect(url_for('dashboard'))

@app.route('/delete/<filename>', methods=['POST'])
@login_required
@vault_access_required(operation_type='write')
def delete_file(filename):
    """Deletes an encrypted file from the user's vault."""
    user = get_current_user_from_session()
    user_vault_path = get_user_vault_path(user['username'], app.config['VAULT_ROOT_DIR'])
    file_to_delete = os.path.join(user_vault_path, filename)
    
    if not os.path.isfile(file_to_delete):
        flash("File not found in your vault.", 'danger')
        log_event(user['username'], f"Attempted deletion of non-existent file {filename}", success=False)
        return redirect(url_for('dashboard'))

    if check_access(user['username'], file_to_delete, 'write'):
        try:
            os.remove(file_to_delete)
            flash(f"File '{filename.replace('.enc', '')}' deleted successfully!", 'success')
            log_event(user['username'], f"Deleted {filename}")
        except Exception as e:
            flash(f"Error deleting file: {e}", 'danger')
            log_event(user['username'], f"Failed deletion of {filename}: {e}", success=False)
    else:
        flash("Access denied to delete file.", 'danger')
        log_event(user['username'], f"Access denied for deletion of {filename}", success=False)
    return redirect(url_for('dashboard'))

@app.route('/verify_integrity/<filename>', methods=['POST'])
@login_required
@vault_access_required(operation_type='read')
def verify_file_integrity_web(filename):
    """Verifies the integrity of an encrypted file using the stored key."""
    user = get_current_user_from_session()
    user_vault_path = get_user_vault_path(user['username'], app.config['VAULT_ROOT_DIR'])
    encrypted_file_path = os.path.join(user_vault_path, filename)

    if not os.path.isfile(encrypted_file_path):
        flash("Encrypted file not found in your vault.", 'danger')
        log_event(user['username'], f"Attempted integrity check of non-existent file {filename}", success=False)
        return redirect(url_for('dashboard'))

    if check_access(user['username'], encrypted_file_path, 'read'):
        try:
            verify_file_integrity(encrypted_file_path, None, user['pass_key'])
            flash(f"Integrity check passed for '{filename.replace('.enc', '')}'!", 'success')
            log_event(user['username'], f"Web integrity check passed for {filename}")
        except ValueError as e:
            flash(f"Integrity check FAILED for '{filename.replace('.enc', '')}': {e}. File might be tampered with or key is wrong!", 'danger')
            log_event(user['username'], f"Web integrity check failed for {filename}: {e}", success=False)
        except Exception as e:
            flash(f"Error during integrity check: {e}", 'danger')
            log_event(user['username'], f"Error during web integrity check for {filename}: {e}", success=False)
    else:
        flash("Access denied to verify file integrity.", 'danger')
        log_event(user['username'], f"Web access denied for integrity check of {filename}", success=False)
    return redirect(url_for('dashboard'))

@app.route('/preview/<filename>')
@login_required
@vault_access_required(operation_type='read')
def preview_file(filename):
    """Serves a decrypted file for preview in the browser."""
    user = get_current_user_from_session()
    user_vault_path = get_user_vault_path(user['username'], app.config['VAULT_ROOT_DIR'])
    encrypted_file_path = os.path.join(user_vault_path, filename)

    if not os.path.isfile(encrypted_file_path):
        abort(404, description="File not found in your vault.")
    
    if check_access(user['username'], encrypted_file_path, 'read'):
        temp_preview_path = None
        try:
            original_filename = filename.replace(".enc", "")
            temp_preview_filename = f"preview_{datetime.now().timestamp()}_{os.path.basename(original_filename)}"
            temp_preview_path = os.path.join(app.config['TEMP_UPLOAD_DIR'], temp_preview_filename)
            
            decrypted_bytes = decrypt_file(encrypted_file_path, user['pass_key'])
            with open(temp_preview_path, 'wb') as f:
                f.write(decrypted_bytes)
            
            log_event(user['username'], f"Web previewed {filename}")
            
            mimetype, _ = guess_type(original_filename)
            if mimetype is None:
                mimetype = 'application/octet-stream' 
                
            @after_this_request
            def remove_temp_preview_file(response):
                """Callback to remove temporary preview file after response is sent."""
                if os.path.exists(temp_preview_path):
                    try:
                        os.remove(temp_preview_path)
                        logging.info(f"Cleaned up temp preview file: {temp_preview_path}")
                    except Exception as e:
                        logging.error(f"Error cleaning up temp preview file {temp_preview_path}: {e}")
                return response
            
            return send_from_directory(app.config['TEMP_UPLOAD_DIR'], temp_preview_filename, mimetype=mimetype)
            
        except ValueError as ve:
            abort(400, description=f"File integrity check failed during decryption for preview: {ve}. File might be tampered with or key is wrong!")
        except Exception as e:
            abort(500, description=f"Error preparing file for preview: {e}")
    else:
        abort(403, description="Access denied to preview file.")

if __name__ == '__main__':
    app.run(debug=True, port=5000)