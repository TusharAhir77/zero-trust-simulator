import sqlite3
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = sqlite3.connect("zerotrust.db")
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        resource TEXT,
        status TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')

    # Add default users (passwords are hashed)
    cursor.execute("INSERT OR IGNORE INTO users VALUES (NULL, 'admin', ?, 'admin')", (hash_password('admin123'),))
    cursor.execute("INSERT OR IGNORE INTO users VALUES (NULL, 'john', ?, 'user')", (hash_password('john123'),))
    cursor.execute("INSERT OR IGNORE INTO users VALUES (NULL, 'guest', ?, 'guest')", (hash_password('guest123'),))

    conn.commit()
    conn.close()
    print("✅ Database initialized!")

init_db()