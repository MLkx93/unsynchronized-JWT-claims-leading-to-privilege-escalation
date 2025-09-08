# app/src/main.py
from flask import Flask, request, jsonify, g
from functools import wraps
import jwt
import datetime
import sqlite3
import os

app = Flask(__name__)
app.config.from_pyfile('config.py')

# Define the database path relative to the app's working directory
DATABASE = os.path.join(app.root_path, 'database.db')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row # Return rows as dicts
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                role TEXT NOT NULL DEFAULT 'Read-Only'
            )
        ''')
        # Insert default users if not exist
        if not cursor.execute("SELECT * FROM users WHERE username='admin'").fetchone():
            cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'adminpass', 'Admin')")
        if not cursor.execute("SELECT * FROM users WHERE username='supervisor'").fetchone():
            cursor.execute("INSERT INTO users (username, password, role) VALUES ('supervisor', 'superpass', 'Supervisor')")
        if not cursor.execute("SELECT * FROM users WHERE username='readonly'").fetchone():
            cursor.execute("INSERT INTO users (username, password, role) VALUES ('readonly', 'readpass', 'Read-Only')")
        db.commit()

# --- JWT Helpers ---
def generate_jwt(user_id, username, role):
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30) # Token expiry
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_jwt(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None # Token has expired
    except jwt.InvalidTokenError:
        return None # Invalid token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        current_user = verify_jwt(token)
        if not current_user:
            return jsonify({'message': 'Token is invalid or expired!'}), 401

        g.current_user = current_user # Store user info in global context
        return f(*args, **kwargs)
    return decorated

def roles_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not g.current_user or g.current_user['role'] not in allowed_roles:
                return jsonify({'message': 'Insufficient privileges'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- API Endpoints ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    db = get_db()
    cursor = db.cursor()
    user = cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()

    if user:
        token = generate_jwt(user['id'], user['username'], user['role'])
        return jsonify({'message': 'Logged in successfully', 'token': token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/profile', methods=['GET'])
@token_required
def get_profile():
    db = get_db()
    cursor = db.cursor()
    user_id = g.current_user['user_id']
    user = cursor.execute("SELECT username, email, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        return jsonify(dict(user)), 200
    return jsonify({'message': 'User not found'}), 404

# !!! VULNERABLE ENDPOINT !!!
@app.route('/profile', methods=['POST'])
@token_required
def update_profile():
    data = request.get_json()
    new_email = data.get('email')
    user_id = g.current_user['user_id'] # Get user_id from the *current* JWT
    current_jwt_role = g.current_user['role'] # Role from the JWT

    db = get_db()
    cursor = db.cursor()

    original_db_user = cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not original_db_user:
        return jsonify({'message': 'User not found in DB.'}), 404

    original_db_role = original_db_user['role']

    # --- SIMULATED VULNERABILITY: Temporary Privilege Escalation during update ---
    # This is where the core vulnerability is injected. In a real app, this might be
    # due to a complex multi-step process, an incorrect SQL update, or a race condition
    # where an Admin's action to update *another* user's role briefly puts them in Admin.

    # For this lab, we'll simulate it: if a 'readonly' user tries to update their profile,
    # for a *brief moment*, the backend will *incorrectly* elevate their role to Admin in the DB
    # before setting it back, allowing them to re-issue an Admin JWT.
    # THIS IS NOT HOW IT SHOULD BE DONE! It's for demonstration.

    transaction_started = False
    try:
        # Start a transaction if needed for more complex scenarios
        # For SQLite, each execute is a transaction unless explicitly managed.
        # This block simulates the "window" where a bad state exists.

        # CRITICAL INJECTION POINT FOR VULNERABILITY:
        # Temporarily elevate the user's role to Admin in the DB for a brief window
        # if they are a 'Read-Only' user. This simulates a real-world bug.
        if original_db_role == 'Read-Only':
            app.logger.warning(f"VULNERABILITY: Temporarily elevating user {original_db_user['username']} to Admin in DB.")
            cursor.execute("UPDATE users SET role = ? WHERE id = ?", ('Admin', user_id))
            db.commit() # Commit the temporary elevation
            transaction_started = True # Indicate that a change was made

        # Update email (this is the legitimate part of the request)
        if new_email:
            cursor.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
            db.commit() # Commit email update (and keep temporary role if it was elevated)

        # --- Vulnerable JWT re-issuance logic ---
        # After the (potentially vulnerable) update, we fetch the *current* role from DB
        # and re-issue a JWT. If the role was temporarily elevated, the re-issued JWT
        # will contain the elevated role.
        updated_db_user = cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if updated_db_user and updated_db_user['role'] != current_jwt_role:
            new_jwt = generate_jwt(updated_db_user['id'], updated_db_user['username'], updated_db_user['role'])
            app.logger.info(f"VULNERABILITY TRIGGERED: User {updated_db_user['username']} got a new JWT with role: {updated_db_user['role']}")
            return jsonify({
                'message': 'Profile updated successfully!',
                'new_jwt': new_jwt,
                'current_db_role': updated_db_user['role'],
                'original_jwt_role': current_jwt_role
            }), 200
        
        return jsonify({'message': 'Profile updated successfully!', 'current_db_role': original_db_role}), 200

    finally:
        # After the vulnerable window, revert the role back to what it should be if it was 'Read-Only'
        # This ensures the database state eventually becomes consistent, but the JWT exploit happens first.
        if transaction_started and original_db_role == 'Read-Only':
             app.logger.warning(f"VULNERABILITY: Reverting user {original_db_user['username']} role from Admin back to Read-Only in DB.")
             cursor.execute("UPDATE users SET role = ? WHERE id = ?", ('Read-Only', user_id))
             db.commit()


@app.route('/admin/dashboard', methods=['GET'])
@token_required
@roles_required(['Admin'])
def admin_dashboard():
    return jsonify({'message': f"Welcome, Admin {g.current_user['username']}! This is the Admin Dashboard."}), 200

@app.route('/supervisor/reports', methods=['GET'])
@token_required
@roles_required(['Admin', 'Supervisor'])
def supervisor_reports():
    return jsonify({'message': f"Welcome, Supervisor/Admin {g.current_user['username']}! Here are your reports."}), 200

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)