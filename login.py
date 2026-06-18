from flask import request
import sqlite3

def login():
    username = request.args.get("username")
    pw = request.args.get("password")
    query = "SELECT * FROM users WHERE name=\"" + username + "\""
    conn = sqlite3.connect("db.sqlite3")
    conn.execute(query)
