import os
import pickle
import subprocess
from flask import Flask, request

app = Flask(__name__)

# Hardcoded secret (security risk)
SECRET_KEY = "password123"

# SQL Injection vulnerability
def sql_injection(username):
    import sqlite3
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '{}'".format(username)  # Unsafe formatting
    cursor.execute(query)
    return cursor.fetchall()

# Command Injection vulnerability
def run_command(command):
    output = os.system(command)  # Dangerous: executes arbitrary commands
    return output

# Insecure deserialization
def deserialize_data(data):
    return pickle.loads(data)  # Risky: unpickling untrusted data

# Use of insecure hash function (MD5)
def insecure_hash(password):
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()

# Path traversal vulnerability
def read_file(filename):
    with open(filename, 'r') as f:  # No validation of 'filename'
        return f.read()

# Outdated dependency (e.g., using deprecated 'requests' methods)
def insecure_http_request():
    import requests
    response = requests.get('http://example.com', verify=False)  # Disabled SSL verification
    return response.text

if __name__ == "__main__":
    app.run(debug=True)  # Debug mode enabled in production (security risk)
