import csv
import datetime
import pytz
import requests
import subprocess
import urllib
import uuid

from flask import redirect, render_template, session,flash
from functools import wraps
from tables import db


# check password not digite
def isAllPassword_Digite(password):
    for char in password:
        if char.isdigit():
            return True
        return False

# check username not already existe
def isUsernameAlreadyExiste(name):
    row = db.execute(
        """
           SELECT * FROM users
           WHERE users.name = ?
        """,
        name,
    )
    if len(row) != 0:
        return True
    return False





def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function




def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("You must be logged in to access this page.", "warning")
            return redirect("/login")

        user_id = session["user_id"]
        user = db.execute(
            """
            SELECT * FROM users
            WHERE id = ?
            """,
            user_id,
        )

        if user[0]["role"] == "Admin":
            return f(*args, **kwargs)
        else:
            flash("You are not authorized to access this page.", "danger")
            return redirect("/login")

    return decorated_function
