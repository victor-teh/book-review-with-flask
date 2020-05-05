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
            return render_template("search.html", login=session["login"])

    else:
        # clear session if they submit a post request directly, be sure to log them out first
        session.clear()
        session["login"] = False

        # get username password from form
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        # check if username exist
        if db.execute("SELECT username from users WHERE username=:username", {"username": username}).rowcount == 0:
            message = "Invalid username or password"
            return render_template("index.html", danger_message=message, login=session["login"])
        else:
            # compare pw with pwhash in db
            user = db.execute(
                "SELECT * from users WHERE username=:username", {"username": username}).fetchone()
            db_password = user["password"]
            if bcrypt.check_password_hash(db_password, password):
                session["login"] = True
                session["user_name"] = user["name"]
                session["user_id"] = user["id"]
                return render_template("search.html", login=session["login"])
            else:
                message = "Invalid username or password"
                return render_template("index.html", dander_message=message, login=session["login"])


@app.route("/logout", methods=["GET", "POST"])
def logout():
    if request.method == 'GET':
        session.clear()
        session["login"] = False
        message = "Successfully Logout"
        return render_template("index.html", success_message=message, login=session["login"])

    else:
        # clear session if they submit a post request directly, be sure to log them out first
        session.clear()
        session["login"] = False

        # get username password from form
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        # check if username exist
        if db.execute("SELECT username from users WHERE username=:username", {"username": username}).rowcount == 0:
            message = "Invalid username or password"
            return render_template("index.html", danger_message=message, login=session["login"])
        else:
            # compare pw with pwhash in db
            user = db.execute(
                "SELECT * from users WHERE username=:username", {"username": username}).fetchone()
            db_password = user["password"]
            if bcrypt.check_password_hash(db_password, password):
                session["login"] = True
                session["user_name"] = user["name"]
                return render_template("search.html", login=session["login"])
            else:
                message = "Invalid username or password"
                return render_template("index.html", dander_message=message, login=session["login"])


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

        if len(username) <= 0 and len(password) <= 0 and len(name) <= 0:
            message="Enter all required fields"
            return render_template("register.html", warning_message=message)
        elif db.execute("SELECT username from users WHERE username=:username", {"username": username}).rowcount != 0:
            message="Username taken"
            return render_template("register.html", warning_message=message)
        else:
            # hashing password with bcrypt hashing
            pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            db.execute("INSERT INTO users (username, password, name) VALUES (:username, :password, :name)", {
                       "username": username, "password": pw_hash, "name": name})
            db.commit()

            message = "Registered successfully!"
        return render_template("index.html", success_message=message, login=session["login"])


@app.route("/search", methods=["GET", "POST"])
def search():
    if request.method == 'GET':
        return render_template("search.html", login=session["login"])
    else:
        search = "%" + request.form.get("search").lower() + "%"
        results = db.execute(
            "SELECT * FROM books WHERE lower(title) LIKE :search OR lower(author) LIKE :search OR lower(isbn) LIKE :search", {"search": search}).fetchall()

        if db.execute(
            "SELECT * FROM books WHERE lower(title) LIKE :search OR lower(author) LIKE :search OR lower(isbn) LIKE :search", {"search": search}).rowcount==0:
            message="No such book."
            return render_template("search.html", danger_message=message, login=session["login"])
        else:
            return render_template("search.html", results=results, login=session["login"])


@app.route("/books/<int:book_id>", methods=["GET", "POST"])
def book(book_id):
    # Lists details about a single book.
    # Make sure book exists.
    book = db.execute("SELECT * FROM books WHERE id = :id",
                      {"id": book_id}).fetchone()

    reviews = db.execute("SELECT users.name, reviews.review, reviews.rating FROM reviews INNER JOIN users ON users.id = reviews.user_id WHERE reviews.book_id=:book_id ", {
                         "book_id": book_id}).fetchall()

    if request.method == 'GET':
        return render_template("book.html", book=book, reviews=reviews, login=session["login"])
    else:
        rating = -1
        # get rating and review from form
        rating = int(request.form.get("rating"))
        review = request.form.get("review").strip()

        if rating < 0 or len(review) <= 0:
            message = "Invalid Review. Please rate and write a review before submit."
            return render_template("book.html", book=book, danger_message=message, reviews=reviews, login=session["login"])
        else:
            db.execute("INSERT INTO reviews (user_id, book_id, review, rating) VALUES (:user_id, :book_id, :review, :rating)", {
                       "user_id": session["user_id"], "book_id": book_id, "review": review, "rating": rating})
            db.commit()
            message = "Review submitted successfully!"
            return render_template("book.html", book=book, success_message=message, reviews=reviews, login=session["login"])
