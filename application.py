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

@app.route("/", methods=["GET", "POST"])
def index():
    
    if request.method == 'GET':
        if session.get("user_name") is None:
            session["login"] = False
            return render_template("index.html", login=session["login"])
        else: 
            user_name = session["user_name"]
            return render_template("index.html", user_name=user_name, login=session["login"])
 
    else:
        # clear session if they submit a post request directly, be sure to log them out first
        session.clear()
        session["login"] = False
        
        # get username password from form
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        # check if username exist
        if db.execute("SELECT username from users WHERE username=:username",{"username": username}).rowcount == 0:
            message = "Invalid username or password"
            return render_template("index.html", message=message, login=session["login"])
        else :
            # compare pw with pwhash in db
            user = db.execute("SELECT * from users WHERE username=:username", {"username": username}).fetchone()
            db_password = user["password"]
            if bcrypt.check_password_hash(db_password, password):
                session["login"] = True
                session["user_name"] = user["name"]
                message = "Log In Successfully!"
                return render_template("index.html", message=message, user_name=session["user_name"], login=session["login"])
            else:
                message = "Invalid username or password"
                return render_template("index.html", message=message, login=session["login"])
@app.route("/logout")
def logout():
    session.clear()
    session["login"] = False
    message = "Successfully Logout"
    return render_template("index.html", message=message, login=session["login"])

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    else:
        session.clear()
        session["login"] = False

        # get username password and name from form
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        name = request.form.get("name").strip()

        if len(username)<0 and len(password)<0 and len(name)<0:
            return render_template("register.html", message="Enter all required fields")
        elif db.execute("SELECT username from users WHERE username=:username", {"username": username}).rowcount != 0 :
            return render_template("register.html", message="Username taken")
        else:
            # hashing password with bcrypt hashing
            pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            db.execute("INSERT INTO users (username, password, name) VALUES (:username, :password, :name)", {"username": username, "password": pw_hash, "name": name})
            db.commit()
            
            message = "Registered successfully!"
        return render_template("index.html", message=message, login=session["login"])

@app.route("/search")
def search():
    return render_template("search.html")




# @app.route("/<string:name>")
# def hello(name):
#     return f"Hello,{name}"



