import csv
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))

# CASCADE = if a record in the parent table is deleted, then the corresponding records in the child table will automatically be deleted.
engine.execute("DROP TABLE books CASCADE")
engine.execute("DROP TABLE users CASCADE")
engine.execute("DROP TABLE reviews CASCADE")

engine.execute("CREATE TABLE books ( id SERIAL PRIMARY KEY, isbn VARCHAR  UNIQUE NOT NULL, title VARCHAR NOT NULL, author VARCHAR NOT NULL, year INTEGER NOT NULL)")
engine.execute("CREATE TABLE users ( id SERIAL PRIMARY KEY, username VARCHAR UNIQUE NOT NULL, password VARCHAR NOT NULL, name VARCHAR NOT NULL)")
engine.execute("CREATE TABLE reviews ( id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users, book_id INTEGER REFERENCES books, review VARCHAR NOT NULL, rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5))")

def main():
    f = open("books.csv")
    books = csv.reader(f)
    for isbn, title, author, year in books:
        db.execute("INSERT INTO books (isbn, title, author, year) VALUES (:isbn, :title, :author, :year)",
                    {"isbn": isbn, "title": title, "author": author, "year": year})
        print(f"Added book: {title}")
    db.commit()

if __name__ == "__main__":
    main()
