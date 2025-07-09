import os
import logging

logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_user_vault_path(username, vault_root_dir='vault_data'):
    """
    Constructs the absolute path to a user's vault folder.
    """
    if not os.path.isabs(vault_root_dir):
        vault_root_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', vault_root_dir)
        vault_root_dir = os.path.normpath(vault_root_dir)
    
    user_vault_path = os.path.join(vault_root_dir, username)
    return user_vault_path

def create_vault_folder_for_user(username, vault_root_dir='vault_data'):
    """
    Creates a dedicated vault folder for a new user if it doesn't exist.
    """
    user_vault_path = get_user_vault_path(username, vault_root_dir)
    try:
        os.makedirs(user_vault_path, exist_ok=True)
        logging.info(f"Vault folder ensured for user '{username}' at '{user_vault_path}'.")
        return True
    except OSError as e:
        logging.error(f"Failed to create vault folder for user '{username}': {e}")
        return False

def check_access(username, file_path, operation_type):
    """
    Checks if the user has permission for a specific operation on a file.
    In this simplified model, a user has full access to files within their own vault.
    Future: This could be extended with more granular permissions (e.g., sharing).
    """
    user_vault_root = get_user_vault_path(username)
    
    normalized_file_path = os.path.normpath(file_path)
    normalized_user_vault_root = os.path.normpath(user_vault_root)

    if not normalized_file_path.startswith(normalized_user_vault_root):
        logging.warning(f"Security alert: User '{username}' attempted to access file outside their vault: {file_path}")
        return False

    logging.info(f"Access granted for user '{username}' to perform '{operation_type}' on '{os.path.basename(file_path)}'.")
    return True