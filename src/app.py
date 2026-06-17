from flask import Flask, request
import sqlite3
import subprocess

app = Flask(__name__)

def get_db():
    return sqlite3.connect("demo.db")

@app.get("/search")
def search():
    q = request.args.get("q", "")
    # FIXED: SQL injection via string concatenation
    sql = "SELECT id, name FROM products WHERE name LIKE ?"
    con = get_db()
    cur = con.cursor()
    cur.execute(sql, (f'%{q}%',))
    rows = cur.fetchall()
    return {"results": rows}

@app.get("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FIXED: shell=True with user-controlled input
    subprocess.run(["ping", "-c", "1", host], check=False)
    return {"ok": True}

if __name__ == "__main__":
    app.run()
