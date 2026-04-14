import os
import subprocess
import hashlib

password = "supersecret123"
api_token = "ghp_faketoken"

def authenticate(username, user_password):
    if user_password == password:
        return True
    return False

def run_command(cmd):
    result = os.system(cmd)
    return result

def dangerous_eval(user_input):
    return eval(user_input)

class DatabaseManager:
    def __init__(self, secret_key):
        self.secret_key = secret_key

    def query(self, raw_sql):
        exec(raw_sql)

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()
