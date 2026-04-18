# VulnFlask -- Deliberately Vulnerable Demo Application

This application exists solely as a scan target for MISTCODER.
It is intentionally insecure.

## Vulnerabilities (intentional)

| ID   | Category              | Route     | Description                         |
|------|-----------------------|-----------|-------------------------------------|
| V-01 | COMMAND_INJECTION     | /ping     | os.system with unsanitized input    |
| V-02 | DANGEROUS_CALL        | /calc     | eval() on user-supplied expression  |
| V-03 | HARDCODED_SECRET      | module    | DB password, API key hardcoded      |
| V-04 | SQL_INJECTION         | /login    | String-formatted SQL query          |
| V-05 | INSECURE_DESERIAL     | /load     | pickle.loads on raw POST body       |
| V-06 | PATH_TRAVERSAL        | /file     | open() with user-controlled path    |
| V-07 | XSS                   | /greet    | User input in render_template_string|
| V-08 | HARDCODED_SECRET      | module    | Flask secret_key hardcoded          |
| V-09 | SECRET_EXPOSURE       | /debug    | Credentials returned in response    |
| V-10 | SECRET_EXPOSURE       | USERS     | Plaintext password store            |

## Running the demo scan

    python sandbox/run_demo.py

Do NOT deploy this application anywhere. It is a scan target only.
