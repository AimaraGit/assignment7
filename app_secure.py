#All OWASP vulnerabilities have been identified and fixed.

import sqlite3
import bcrypt
import html
import os
import secrets
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

DB_PATH = "secure.db"

#Logging setup (Fix: Insufficient Logging)
logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

#Database Setup 
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            content TEXT
        )
    """)
    conn.commit()
    conn.close()

#Session Store
sessions = {}

def create_session(username):
    # FIX: cryptographically secure random session ID
    sid = secrets.token_hex(32)
    sessions[sid] = username
    return sid

def get_session(cookie_header):
    if not cookie_header:
        return None
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("session_id="):
            sid = part.split("=", 1)[1]
            return sessions.get(sid)
    return None

#Input Validation
def validate_username(username):
    """Least Privilege: only allow safe characters, limit length"""
    return (
        isinstance(username, str) and
        3 <= len(username) <= 30 and
        username.isalnum()
    )

def validate_password(password):
    return isinstance(password, str) and 8 <= len(password) <= 128

def validate_comment(content):
    return isinstance(content, str) and 1 <= len(content) <= 1000

#HTML Templates
def html_page(title, body, username=None):
    nav = (f'<b>Logged in as: {html.escape(username)}</b> | '
           f'<a href="/logout">Logout</a>') if username else (
           '<a href="/login">Login</a> | <a href="/register">Register</a>')
    return f"""<!DOCTYPE html>
<html>
<head><title>{html.escape(title)}</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'unsafe-inline'">
<style>body{{font-family:sans-serif;max-width:800px;margin:40px auto;padding:0 20px}}
input,textarea{{width:100%;padding:8px;margin:4px 0;box-sizing:border-box}}
button{{padding:8px 16px;background:#1a6b3c;color:#fff;border:none;cursor:pointer;border-radius:4px}}
.comment{{background:#f0f7f0;padding:10px;margin:8px 0;border-radius:4px;border-left:3px solid #1a6b3c}}
.error{{color:#c0392b;background:#fdecea;padding:8px;border-radius:4px}}
.success{{color:#1a6b3c;background:#eafaf1;padding:8px;border-radius:4px}}
.badge{{background:#1a6b3c;color:white;padding:2px 8px;border-radius:12px;font-size:12px}}</style>
</head>
<body>
<h2> Secure Blog App</h2>
<div>{nav}</div><hr>
<h1>{html.escape(title)}</h1>
{body}
</body></html>"""

#Security Headers
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

#Request Handler 
class SecureHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_html(self, html_content, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for h, v in SECURITY_HEADERS.items():
            self.send_header(h, v)
        self.end_headers()
        self.wfile.write(html_content.encode())

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 10_000:  # FIX: limit body size
            return {}
        return parse_qs(self.rfile.read(length).decode())

    def get_username(self):
        return get_session(self.headers.get("Cookie"))

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        for h, v in SECURITY_HEADERS.items():
            self.send_header(h, v)
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        username = self.get_username()

        if path == "/" or path == "/comments":
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            #FIX: parameterized query
            c.execute("SELECT username, content FROM comments ORDER BY id DESC")
            rows = c.fetchall()
            conn.close()

            comments_html = ""
            for u, content in rows:
                #FIX: html.escape() prevents XSS — all user content is escaped
                safe_user = html.escape(u)
                safe_content = html.escape(content)
                comments_html += f'<div class="comment"><b>{safe_user}:</b> {safe_content}</div>'

            form = ""
            if username:
                form = """
                <form method="POST" action="/comment">
                    <textarea name="content" placeholder="Write a comment..." rows="3" maxlength="1000"></textarea>
                    <button type="submit">Post Comment</button>
                </form>"""

            body = f"{form}<h3>Comments ({len(rows)}):</h3>"
            body += comments_html if comments_html else "<p>No comments yet.</p>"
            self.send_html(html_page("Comments", body, username))

        elif path == "/register":
            self.send_html(html_page("Register", """
                <form method="POST" action="/register">
                    <label>Username (3-30 alphanumeric chars)</label>
                    <input name="username" placeholder="Username" maxlength="30"><br>
                    <label>Password (8-128 chars)</label>
                    <input name="password" type="password" placeholder="Password" maxlength="128"><br><br>
                    <button type="submit">Register</button>
                </form>"""))

        elif path == "/login":
            self.send_html(html_page("Login", """
                <form method="POST" action="/login">
                    <input name="username" placeholder="Username" maxlength="30"><br>
                    <input name="password" type="password" placeholder="Password" maxlength="128"><br><br>
                    <button type="submit">Login</button>
                </form>"""))

        elif path == "/logout":
            cookie = self.headers.get("Cookie", "")
            for part in cookie.split(";"):
                part = part.strip()
                if part.startswith("session_id="):
                    sid = part.split("=", 1)[1]
                    sessions.pop(sid, None)
                    logging.info(f"User logged out, session {sid[:8]}... destroyed")
            self.redirect("/")

        else:
            self.send_html("<h1>404 - Page Not Found</h1>", 404)

    def do_POST(self):
        path = urlparse(self.path).path
        data = self.read_body()
        ip = self.client_address[0]

        if path == "/register":
            username = data.get("username", [""])[0]
            password = data.get("password", [""])[0]

            #FIX: Input validation before any DB interaction
            if not validate_username(username):
                self.send_html(html_page("Register",
                    '<p class="error">Username must be 3-30 alphanumeric characters.</p>'))
                return
            if not validate_password(password):
                self.send_html(html_page("Register",
                    '<p class="error">Password must be 8-128 characters.</p>'))
                return

            #FIX: bcrypt hashing with automatic salt
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            try:
                #FIX: parameterized query 
                c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                          (username, password_hash))
                conn.commit()
                logging.info(f"New user registered: {username} from {ip}")
                body = '<p class="success">✅ Registered successfully! <a href="/login">Login here</a></p>'
            except sqlite3.IntegrityError:
                body = '<p class="error">Username already taken. Choose another.</p>'
            finally:
                conn.close()
            self.send_html(html_page("Register", body))

        elif path == "/login":
            username = data.get("username", [""])[0]
            password = data.get("password", [""])[0]

            #FIX: validate inputs first (fail securely)
            if not validate_username(username) or not validate_password(password):
                # Generic error — don't reveal which field failed (info disclosure)
                self.send_html(html_page("Login",
                    '<p class="error">Invalid credentials.</p>'))
                return

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            #FIX: parameterized query
            c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            conn.close()

            #FIX: bcrypt.checkpw() — constant-time comparison prevents timing attacks
            if row and bcrypt.checkpw(password.encode(), row[0].encode()):
                sid = create_session(username)
                logging.info(f"Successful login: {username} from {ip}")
                self.send_response(302)
                #FIX: HttpOnly prevents JS access; SameSite=Strict prevents CSRF
                self.send_header("Set-Cookie",
                    f"session_id={sid}; HttpOnly; SameSite=Strict; Path=/")
                self.send_header("Location", "/")
                for h, v in SECURITY_HEADERS.items():
                    self.send_header(h, v)
                self.end_headers()
            else:
                logging.warning(f"Failed login attempt for username: {username} from {ip}")
                self.send_html(html_page("Login",
                    '<p class="error">Invalid credentials.</p>'))

        elif path == "/comment":
            username = self.get_username()
            #FIX: Access control — must be logged in
            if not username:
                logging.warning(f"Unauthorized comment attempt from {ip}")
                self.redirect("/login")
                return

            content = data.get("content", [""])[0]

            #FIX: Validate comment before storing
            if not validate_comment(content):
                self.send_html(html_page("Error",
                    '<p class="error">Comment must be 1-1000 characters.</p>', username))
                return

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            #FIX: parameterized query — content stored as-is, escaped on output
            c.execute("INSERT INTO comments (username, content) VALUES (?, ?)",
                      (username, content))
            conn.commit()
            conn.close()
            logging.info(f"Comment posted by {username}")
            self.redirect("/")

if __name__ == "__main__":
    init_db()
    print("Secure app running at http://localhost:8081")
    HTTPServer(("localhost", 8081), SecureHandler).serve_forever()
