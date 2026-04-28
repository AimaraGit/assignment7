#Vulnerabilities: SQL Injection, XSS, Broken Auth, No password hashing, etc.
import sqlite3
import hashlib
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import os

DB_PATH = "insecure.db"

#Database Setup 
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    #VULNERABILITY: passwords stored as plain MD5 (weak hashing)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
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

def weak_hash(password):
    #VULNERABILITY: MD5 is broken, no salt
    return hashlib.md5(password.encode()).hexdigest()

#Simple session store (in-memory, not secure) 
sessions = {}

def get_session(cookie_header):
    if not cookie_header:
        return None
    for part in cookie_header.split(";"):
        if "session_id=" in part:
            sid = part.strip().split("=")[1]
            return sessions.get(sid)
    return None

#HTML Templates 
def html_page(title, body, username=None):
    nav = f'<b>Logged in as: {username}</b> | <a href="/logout">Logout</a>' if username else '<a href="/login">Login</a> | <a href="/register">Register</a>'
    return f"""<!DOCTYPE html>
<html>
<head><title>{title}</title>
<style>body{{font-family:sans-serif;max-width:800px;margin:40px auto;padding:0 20px}}
input,textarea{{width:100%;padding:8px;margin:4px 0}}
button{{padding:8px 16px;background:#333;color:#fff;border:none;cursor:pointer}}
.comment{{background:#f5f5f5;padding:10px;margin:8px 0;border-radius:4px}}
.error{{color:red}} .success{{color:green}}</style>
</head>
<body>
<h2> Insecure Blog App</h2>
<div>{nav}</div><hr>
<h1>{title}</h1>
{body}
</body></html>"""

#Request Handler 
class InsecureHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # silence default logs

    def send_html(self, html, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return parse_qs(self.rfile.read(length).decode())

    def get_username(self):
        return get_session(self.headers.get("Cookie"))

    def do_GET(self):
        path = urlparse(self.path).path
        username = self.get_username()

        if path == "/" or path == "/comments":
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT username, content FROM comments ORDER BY id DESC")
            rows = c.fetchall()
            conn.close()
            comments_html = ""
            for u, content in rows:
                # VULNERABILITY: raw user content inserted directly (XSS)
                comments_html += f'<div class="comment"><b>{u}:</b> {content}</div>'
            form = ""
            if username:
                form = f"""
                <form method="POST" action="/comment">
                    <textarea name="content" placeholder="Write a comment..." rows="3"></textarea>
                    <button type="submit">Post</button>
                </form>"""
            body = f"{form}<h3>Comments:</h3>{comments_html}" if comments_html or form else "<p>No comments yet.</p>" + form
            self.send_html(html_page("Comments", body, username))

        elif path == "/register":
            self.send_html(html_page("Register", """
                <form method="POST" action="/register">
                    <input name="username" placeholder="Username"><br>
                    <input name="password" type="password" placeholder="Password"><br>
                    <button type="submit">Register</button>
                </form>"""))

        elif path == "/login":
            self.send_html(html_page("Login", """
                <form method="POST" action="/login">
                    <input name="username" placeholder="Username"><br>
                    <input name="password" type="password" placeholder="Password"><br>
                    <button type="submit">Login</button>
                </form>"""))

        elif path == "/logout":
            cookie = self.headers.get("Cookie", "")
            for part in cookie.split(";"):
                if "session_id=" in part:
                    sid = part.strip().split("=")[1]
                    sessions.pop(sid, None)
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()

        else:
            self.send_html("<h1>404 Not Found</h1>", 404)

    def do_POST(self):
        path = urlparse(self.path).path
        data = self.read_body()

        if path == "/register":
            username = data.get("username", [""])[0]
            password = data.get("password", [""])[0]
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            try:
                #VULNERABILITY: MD5 hashing, no input validation
                c.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{weak_hash(password)}')")
                conn.commit()
                body = '<p class="success">Registered! <a href="/login">Login here</a></p>'
            except sqlite3.IntegrityError:
                body = '<p class="error">Username already taken.</p>'
            finally:
                conn.close()
            self.send_html(html_page("Register", body))

        elif path == "/login":
            username = data.get("username", [""])[0]
            password = data.get("password", [""])[0]
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            #VULNERABILITY: SQL Injection — string interpolation in query
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{weak_hash(password)}'"
            c.execute(query)
            user = c.fetchone()
            conn.close()
            if user:
                import random, string
                #VULNERABILITY: weak session ID
                sid = "".join(random.choices(string.ascii_lowercase, k=8))
                sessions[sid] = username
                self.send_response(302)
                #VULNERABILITY: no HttpOnly, no Secure flag on cookie
                self.send_header("Set-Cookie", f"session_id={sid}")
                self.send_header("Location", "/")
                self.end_headers()
            else:
                self.send_html(html_page("Login", '<p class="error">Invalid credentials.</p>'))

        elif path == "/comment":
            username = self.get_username()
            if not username:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            content = data.get("content", [""])[0]
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            #VULNERABILITY: SQL Injection + XSS (no escaping)
            c.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (username, content))
            conn.commit()
            conn.close()
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()

if __name__ == "__main__":
    init_db()
    print("Insecure app running at http://localhost:8080")
    HTTPServer(("localhost", 8080), InsecureHandler).serve_forever()
