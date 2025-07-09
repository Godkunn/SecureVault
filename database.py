import sqlite3
import os

DATABASE_FILE = 'vault.db'

def get_db_connection():
    """
    Establishes and returns a database connection.
    Configures row_factory for dictionary-like access to rows.
    """
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_file=DATABASE_FILE):
    """
    Initializes the database schema if tables do not exist.
    """
    global DATABASE_FILE
    DATABASE_FILE = db_file

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash BLOB NOT NULL, -- Storing hashed password + salt as BLOB
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create audit_log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_description TEXT NOT NULL,
                status TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        print(f"Database '{DATABASE_FILE}' initialized successfully (or already exists).")
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
    finally:
        conn.close()

if __name__ == '__main__':

    init_db()
    print("Database initialization script finished.")