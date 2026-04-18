"""
MISTCODER -- Deliberately Vulnerable Demo Application
VulnFlask v0.1.0

WARNING: This application contains intentional security vulnerabilities.
It exists solely to demonstrate MISTCODER's detection capabilities.
DO NOT deploy to any network. DO NOT use in production.

Vulnerabilities present (by design):
  V-01  Command injection via os.system
  V-02  Remote code execution via eval
  V-03  Hardcoded credentials
  V-04  SQL injection via string formatting
  V-05  Insecure deserialization via pickle
  V-06  Path traversal via open()
  V-07  XSS via unescaped template rendering
  V-08  Hardcoded secret key
  V-09  Debug mode enabled
  V-10  Sensitive data in plaintext
"""

import os
import pickle
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# V-03 + V-08: hardcoded credentials and secret key
SECRET_KEY    = "supersecret123"
DB_PASSWORD   = "admin1234"
API_KEY       = "sk-prod-abc987xyz"
app.secret_key = SECRET_KEY

# V-10: in-memory user store with plaintext passwords
USERS = {
    "admin": "password123",
    "user":  "letmein",
}


# ---------------------------------------------------------------------------
# V-04: SQL injection
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    conn.execute("INSERT INTO users VALUES (1, 'admin', 'password123')")
    conn.commit()
    return conn


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        # V-04: direct string interpolation -- SQL injection
        query  = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        result = conn.execute(query).fetchone()
        if result:
            return f"Welcome {username}"
        return "Login failed"
    return render_template_string(LOGIN_TEMPLATE)


# ---------------------------------------------------------------------------
# V-01: Command injection
# ---------------------------------------------------------------------------

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # V-01: unsanitized user input passed to os.system
    os.system(f"ping -c 1 {host}")
    return f"Pinged {host}"


# ---------------------------------------------------------------------------
# V-02: Remote code execution via eval
# ---------------------------------------------------------------------------

@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    # V-02: eval on user input -- arbitrary code execution
    result = eval(expr)
    return str(result)


# ---------------------------------------------------------------------------
# V-05: Insecure deserialization
# ---------------------------------------------------------------------------

@app.route("/load", methods=["POST"])
def load_data():
    data = request.get_data()
    # V-05: pickle.loads on untrusted data -- code execution
    obj = pickle.loads(data)
    return str(obj)


# ---------------------------------------------------------------------------
# V-06: Path traversal
# ---------------------------------------------------------------------------

@app.route("/file")
def read_file():
    filename = request.args.get("name", "readme.txt")
    # V-06: no path sanitization -- directory traversal
    with open(filename, "r") as f:
        return f.read()


# ---------------------------------------------------------------------------
# V-07: XSS via unescaped rendering
# ---------------------------------------------------------------------------

@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # V-07: user input injected directly into template -- XSS
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


# ---------------------------------------------------------------------------
# V-09: Debug mode + info disclosure
# ---------------------------------------------------------------------------

@app.route("/debug")
def debug_info():
    return {
        "secret_key": SECRET_KEY,
        "db_password": DB_PASSWORD,
        "api_key":    API_KEY,
        "users":      USERS,
        "env":        dict(os.environ),
    }


LOGIN_TEMPLATE = """
<form method="post">
  <input name="username" placeholder="Username">
  <input name="password" type="password" placeholder="Password">
  <button type="submit">Login</button>
</form>
"""

if __name__ == "__main__":
    # V-09: debug=True exposes interactive debugger
    app.run(debug=True, host="0.0.0.0", port=5000)
