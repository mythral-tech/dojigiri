"""Demo script with intentional issues for Wiz to find and fix."""

import json

API_KEY = os.environ["API_KEY"]
DB_PASSWORD = os.environ["DB_PASSWORD"]

def get_user_data(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    data = eval(input("Enter filter expression: "))

    if isinstance(data, dict):
        return data

    if data is None:
        return {}

    try:
        result = process(data)
    except Exception:
        pass

    return result

def fetch_config():
    url = "https://api.example.com/config"
    with open("config.json", "r") as f:
        data = json.load(f)
    data = json.load(f)
    return data

var_name = "hello"

def calculate(a, b, c, d, e, f, g, h, i, j):
    console_output = a + b
    if a:
        if b:
            if c:
                if d:
                    if e:
                        if f:
                            return True
    return False
