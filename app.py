from flask import Flask, render_template, request, redirect, url_for, session, flash
import hashlib
import os
from flask_bcrypt import Bcrypt
import sqlite3


def init_db():
    conn = sqlite3.connect('./database.db')
    cursor = conn.cursor()
    
    # Create the users table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )''')
    
    # Create the passwords table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        app_name TEXT,
        FOREIGN KEY (username) REFERENCES users(username)
    )''')
    
    # Check if the app_name column exists in the passwords table
    cursor.execute('''PRAGMA table_info(passwords)''')
    columns = cursor.fetchall()
    app_name_exists = any(column[1] == 'app_name' for column in columns)
    
    # Add the app_name column if it doesn't exist
    if not app_name_exists:
        cursor.execute('''ALTER TABLE passwords ADD COLUMN app_name TEXT''')

    conn.commit()
    conn.close()


# Call the function to initialize the database
init_db()


app = Flask(__name__, template_folder="C:\\Users\\mdzaf\\OneDrive\\Desktop\\Passwordmanagementsystem\\Password System\\templates")
bcrypt = Bcrypt(app)
app.secret_key = os.urandom(24)


# Database connection
def get_db_connection():
    conn = sqlite3.connect('./database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database
def init_db():
    conn = get_db_connection()
    with app.open_resource('schema.sql', mode='r') as f:
        conn.cursor().executescript(f.read())
    conn.commit()
    conn.close()


# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if username already exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            # Username already exists, display error message
            flash('Username already exists. Please choose a different username.', 'error')
            conn.close()
            return redirect(url_for('register'))

        # Hash the password
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert new user into database
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        conn.close()

        # Display success message
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# User login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password.')

    return render_template('login.html')

# User logout route
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# Dashboard route (requires login)
@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return redirect(url_for('login'))

# Root URL redirect
@app.route('/')
def index():
    return redirect(url_for('home'))


## Route for adding a new password
@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if 'username' not in session:
        # User is not logged in, redirect to login page
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get the password and application/website name data from the form
        password = request.form['password']
        app_name = request.form['app_name']
        
        # Get the username of the logged-in user from the session
        username = session.get('username')
        
        # Insert the new password and application/website name into the database for the logged-in user
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO passwords (username, password, app_name) VALUES (?, ?, ?)', (username, password, app_name))
        conn.commit()
        conn.close()
        
        # Redirect to the dashboard after adding the password
        flash('Password added successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    # Render the template for adding passwords
    return render_template('add_password.html')



# Route for modifying an existing password
@app.route('/modify_password', methods=['GET', 'POST'])
def modify_password():
    if 'username' not in session:
        # User is not logged in, redirect to login page
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get the password data from the form
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        
        # Get the username of the logged-in user from the session
        username = session.get('username')
        
        # Update the selected password in the database for the logged-in user
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE passwords SET password = ? WHERE username = ? AND password = ?', (new_password, username, old_password))
        conn.commit()
        conn.close()
        
        # Redirect to the dashboard after modifying the password
        flash('Password modified successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    # Render the template for modifying passwords
    return render_template('modify_password.html')


# Route for viewing saved passwords
@app.route('/saved_passwords')
def saved_passwords():
    if 'username' not in session:
        # User is not logged in, redirect to login page
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))

    # Get the username of the logged-in user from the session
    username = session.get('username')
    
    # Fetch saved passwords for the logged-in user
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM passwords WHERE username = ?', (username,))
    passwords = cursor.fetchall()
    conn.close()

    # Render the template for viewing saved passwords
    return render_template('saved_passwords.html', passwords=passwords)


# Route for viewing saved passwords for a specific app or website@app.route('/view_passwords', methods=['POST'])
@app.route('/view_passwords', methods=['POST'])
def view_passwords():
    if 'username' not in session:
        # User is not logged in, redirect to login page
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))

    # Get the selected app or website from the form
    app_name = request.form['app_name']

    # Get the username of the logged-in user from the session
    username = session.get('username')

    # Fetch saved passwords for the selected app or website
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM passwords WHERE username = ? AND app_name = ?', (username, app_name))
    passwords = cursor.fetchall()
    conn.close()

    # Render the template for viewing saved passwords
    return render_template('view_passwords.html', passwords=passwords)


# Home page route
@app.route('/home')
def home():
    return render_template('home.html')


if __name__ == '__main__':
    app.run(debug=True)
