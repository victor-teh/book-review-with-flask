import os

from flask import Flask, session, render_template, request
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/search")
def search():
    return render_template("search.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == 'GET':
        return render_template("signup.html")
    else:
        # get username password and name from form
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        name = request.form.get("name").strip()

        if len(username)<0 and len(password)<0 and len(name)<0:
            return render_template("signup.html", message="Enter all required fields")
        elif db.execute("SELECT username from users where username=:username", {"username": username}).rowcount != 0 :
            return render_template("signup.html", message="Username taken")
        else:
            # hashing password with bcrypt hashing
            pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            db.execute("INSERT INTO users (username, password, name) VALUES (:username, :password, :name)", {"username": username, "password": pw_hash, "name": name})
            db.commit()
            
            message = "Registered successfully!"
        return render_template("login.html", message=message)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'GET':
        return render_template("login.html")
    else:
        # get username password from form
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        

        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        bcrypt.check_password_hash(pw_hash, password).decode('utf-8')
        return render_template("login.html")

@app.route("/logout")
def logout():
    return render_template("logout.html")


# @app.route("/<string:name>")
# def hello(name):
#     return f"Hello,{name}"



