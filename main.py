from flask import Flask, render_template, request
import hashlib
import re

app = Flask(__name__)

HASH_FILE = "hash.txt"


# Password Strength Checker
def check_password_strength(password):

    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letter.")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Add number.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add special character.")

    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    return strength, feedback


# Hash Password
def hash_password(password):

    return hashlib.sha256(password.encode()).hexdigest()


# REGISTER PAGE
@app.route("/", methods=["GET", "POST"])
def index():

    strength = ""
    feedback = []
    message = ""

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        strength, feedback = check_password_strength(password)

        hashed_password = hash_password(password)

        with open(HASH_FILE, "a") as file:
            file.write(f"{username}:{hashed_password}\n")

        message = "Registration Successful"

    return render_template(
        "index.html",
        strength=strength,
        feedback=feedback,
        message=message
    )


# LOGIN PAGE
@app.route("/login", methods=["GET", "POST"])
def login():

    login_message = ""

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        hashed_input_password = hash_password(password)

        authenticated = False

        try:

            with open(HASH_FILE, "r") as file:

                for line in file:

                    stored_username, stored_hash = line.strip().split(":")

                    if (
                        username == stored_username and
                        hashed_input_password == stored_hash
                    ):

                        authenticated = True
                        break

        except FileNotFoundError:

            login_message = "No registered users found."

        if authenticated:

            login_message = "Login Successful"

        else:

            login_message = "Invalid Username or Password"

    return render_template(
        "login.html",
        login_message=login_message
    )


if __name__ == "__main__":

    app.run(debug=True)