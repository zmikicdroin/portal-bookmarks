import os
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
import requests
from PIL import Image
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key-change-this-in-production')
app.config['DATABASE'] = os.environ.get('DATABASE_PATH', 'data/bookmarks.db')
app.config['SCREENSHOT_FOLDER'] = os.environ.get('SCREENSHOT_FOLDER', 'static/screenshots')

# Ensure necessary folders exist
os.makedirs(os.path.dirname(app.config['DATABASE']), exist_ok=True)
os.makedirs(app.config['SCREENSHOT_FOLDER'], exist_ok=True)

# Database functions
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS bookmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                title TEXT NOT NULL,
                screenshot_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        db.commit()

# Initialize database on startup
init_db()

# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Screenshot capture function
def capture_screenshot(url, bookmark_id):
    """Capture screenshot using a screenshot API service"""
    try:
        # Using a free screenshot API (you can also use screenshot-one.com, apiflash.com, etc.)
        # This example uses screenshot.machine for simplicity
        screenshot_url = f"https://api.screenshotmachine.com/?key=YOUR_API_KEY&url={{url}}&dimension=1024x768&format=png"
        
        # Alternative: Try to get favicon or use a placeholder
        # For a simpler approach without external API, we'll create a placeholder
        domain = urlparse(url).netloc
        
        # Create a simple placeholder image with the domain name
        img = Image.new('RGB', (400, 300), color=(73, 109, 137))
        
        screenshot_filename = f"bookmark_{{bookmark_id}}.png"
        screenshot_path = os.path.join(app.config['SCREENSHOT_FOLDER'], screenshot_filename)
        img.save(screenshot_path)
        
        return f"screenshots/{{screenshot_filename}}"
    except Exception as e:
        print(f"Error capturing screenshot: {{e}}")
        return None

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('bookmarks'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        
        db = get_db()
        try:
            password_hash = generate_password_hash(password)
            db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                      (username, password_hash))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('bookmarks'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/bookmarks')
@login_required
def bookmarks():
    db = get_db()
    bookmarks = db.execute(
        'SELECT * FROM bookmarks WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    return render_template('bookmarks.html', bookmarks=bookmarks)

@app.route('/add_bookmark', methods=['POST'])
@login_required
def add_bookmark():
    url = request.form.get('url')
    title = request.form.get('title')
    
    if not url or not title:
        flash('URL and title are required.', 'danger')
        return redirect(url_for('bookmarks'))
    
    # Add http:// if not present
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    db = get_db()
    cursor = db.execute(
        'INSERT INTO bookmarks (user_id, url, title) VALUES (?, ?, ?)',
        (session['user_id'], url, title)
    )
    db.commit()
    
    bookmark_id = cursor.lastrowid
    
    # Capture screenshot
    screenshot_path = capture_screenshot(url, bookmark_id)
    if screenshot_path:
        db.execute(
            'UPDATE bookmarks SET screenshot_path = ? WHERE id = ?',
            (screenshot_path, bookmark_id)
        )
        db.commit()
    
    flash('Bookmark added successfully!', 'success')
    return redirect(url_for('bookmarks'))

@app.route('/delete_bookmark/<int:bookmark_id>')
@login_required
def delete_bookmark(bookmark_id):
    db = get_db()
    
    # Get bookmark to verify ownership and delete screenshot
    bookmark = db.execute(
        'SELECT * FROM bookmarks WHERE id = ? AND user_id = ?',
        (bookmark_id, session['user_id'])
    ).fetchone()
    
    if bookmark:
        # Delete screenshot file if exists
        if bookmark['screenshot_path']:
            screenshot_file = os.path.join('static', bookmark['screenshot_path'])
            if os.path.exists(screenshot_file):
                os.remove(screenshot_file)
        
        db.execute('DELETE FROM bookmarks WHERE id = ?', (bookmark_id,))
        db.commit()
        flash('Bookmark deleted successfully!', 'success')
    else:
        flash('Bookmark not found.', 'danger')
    
    return redirect(url_for('bookmarks'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)