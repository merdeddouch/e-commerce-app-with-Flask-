import os
import uuid
from flask import (
    Flask,
    session,
    render_template,
    request,
    Response,
    redirect,
    send_from_directory,
    flash,
    jsonify,
    url_for,
)
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from tables import db
from datetime import datetime
from flask_session import Session
from helpers import (
    login_required,
    apology,
    isAllPassword_Digite,
    isUsernameAlreadyExiste,
    admin_required,
)
from datetime import datetime


# Configure aaplication
app = Flask(__name__)


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Define the upload folder and allowed extensions for product images
UPLOAD_FOLDER = "static/product_img"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# Check if a file has an allowed file extension
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/wishlist", methods=["GET"])
@login_required
def wishlist():
    user_id = session["user_id"]
    empty_wishlist = False
    fav_products = db.execute(
        """
                    SELECT * FROM products
                    INNER JOIN fav_prod ON products.P_id = fav_prod.product_id
                    WHERE fav_prod.user_id = ?
                    """,
        user_id,
    )
    if len(fav_products) == 0:
        empty_wishlist = True
    Categorys = db.execute(
        """
            SELECT * FROM category
            """
    )
    return render_template(
        "wishlist.html",
        fav_products=fav_products,
        empty_wishlist=empty_wishlist,
        Categorys=Categorys,
    )


@app.route("/add_to_wishlist/<int:product_id>", methods=["GET", "POST"])
@login_required
def add_to_wishlist(product_id):
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    db.execute(
        """
            INSERT INTO fav_prod (user_id,product_id)
            VALUES (?,?)
            """,
        user_id,
        product_id,
    )
    return redirect("/")


@app.route("/add_to_cart", methods=["GET"])
@login_required
def cart():
    if "user_id" not in session:
        return redirect("/login")
    user_id = session["user_id"]
    empty_cart = False
    total_price = 0
    PorductsInCart = db.execute(
        """
            SELECT * FROM cart
            JOIN users on users.id = cart.user_id
            JOIN products ON products.P_id = cart.pord_id
            WHERE cart.user_id = ?
            """,
        user_id,
    )
    if len(PorductsInCart) == 0:
        empty_cart = True
    print(empty_cart)
    Categorys = db.execute(
        """
            SELECT * FROM category
            """
    )
    for prod in PorductsInCart:
        total_price += prod["price_unit"] * (1 - prod["promo"]) * prod["quantity"]
    return render_template(
        "cart.html",
        PorductsInCart=PorductsInCart,
        empty_cart=empty_cart,
        Categorys=Categorys,
        total_price=total_price,
        user_id=user_id,
    )


@app.route("/add_to_cart/<int:product_id>", methods=["GET", "POST"])
@login_required
def add_to_cart(product_id):
    if "user_id" not in session:
        return redirect("/login")
    user_id = session["user_id"]
    quantity = int(request.form.get("qty"))
    cart = db.execute(
        """
            SELECT * FROM cart
            JOIN users on users.id = cart.user_id
            JOIN products ON products.P_id = cart.pord_id
            WHERE cart.user_id = ? AND cart.pord_id = ?
        """,
        user_id,
        product_id,
    )

    if len(cart) != 0:
        db.execute(
            """
            UPDATE cart SET quantity= quantity + ?
            WHERE user_id = ? AND pord_id = ?
            """,
            quantity,
            user_id,
            product_id,
        )
    else:
        db.execute(
            """
            INSERT INTO cart (user_id,pord_id,quantity)
            VALUES (?,?,?)
            """,
            user_id,
            product_id,
            quantity,
        )

    return redirect("/")


@app.route("/wishlist/remove/<int:product_id>", methods=["GET", "POST"])
@login_required
def remove(product_id):
    if "user_id" not in session:
        flash("You must be logged in to remove items from your wishlist.", "error")
        return redirect("/login")

    user_id = session["user_id"]
    db.execute(
        """
            DELETE from fav_prod
            WHERE user_id = ? AND product_id = ?
            """,
        user_id,
        product_id,
    )
    flash("Product removed from your wishlist successfully.", "success")
    return redirect("/wishlist")


@app.route("/remove_from_cart/<int:product_id>", methods=["GET", "POST"])
@login_required
def remove_from_cart(product_id):
    if "user_id" not in session:
        return redirect("/login")
    user_id = session["user_id"]
    db.execute(
        """
        DELETE FROM cart
        WHERE user_id = ? AND pord_id = ?
        """,
        user_id,
        product_id,
    )
    return redirect("/add_to_cart")


@app.route("/add_products", methods=["GET", "POST"])
@login_required
@admin_required
def add_products():
    user_id = session["user_id"]

    users = db.execute(
        """
        SELECT * from users
        WHERE users.id = ?
        """,
        user_id,
    )
    Categorys = db.execute(
        """
            SELECT * FROM category
            """
    )

    if users[0]["role"] != "Admin":
        flash("You're not an admin")
        return redirect("/login")
    if request.method == "POST":
        # get data from admin
        product_name = request.form.get("name")
        Description = request.form.get("Description")
        stock = request.form.get("stock")
        Price = request.form.get("price")
        promo = request.form.get("promo")
        Category = request.form.get("Category")
        img = request.files.get("image")

        # validation part

        # check if fildes are not empty
        if (
            not product_name
            or not Description
            or not stock
            or not Price
            or not promo
            or not Category
        ):
            return apology("must provide filds", 400)

        if img is None or img.filename == "":
            return apology("No selected file", 400)

        if not allowed_file(img.filename):
            return apology("Invalide type, must be png , jpg ,jpeg .", 400)

        # save the uploded file

        filename = secure_filename(img.filename)
        img.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        img_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        Category = int(Category)
        stock = int(stock)
        Price = float(Price)
        promo = float(promo)
        db.execute(
            """
            INSERT INTO products (name,description,img_url,price_unit,promo,category_id,stock)
            VALUES (?,?,?,?,?,?,?)
            """,
            product_name,
            Description,
            img_path,
            Price,
            promo,
            Category,
            stock,
        )
        flash("Product added successfully", "success")
        return redirect("/admindashbord")
    return render_template("add_products.html", Categorys=Categorys)


@app.route("/edit_product/<int:product_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_products(product_id):
    user_id = session["user_id"]

    users = db.execute(
        """
        SELECT * from users
        WHERE users.id = ?
        """,
        user_id,
    )

    if users[0]["role"] != "Admin":
        flash("You're not an admin")
        return redirect("/login")
    if request.method == "POST":
        # get data from admin
        product_name = request.form.get("name")
        Description = request.form.get("Description")
        stock = request.form.get("stock")
        Price = request.form.get("price")
        promo = request.form.get("promo")
        Category = request.form.get("Category")
        img = request.files.get("image")

        # validation part

        # check if fildes are not empty
        if (
            not product_name
            or not Description
            or not stock
            or not Price
            or not promo
            or not Category
        ):
            return apology("must provide filds", 400)

        if img is None or img.filename == "":
            return apology("No selected file", 400)

        if not allowed_file(img.filename):
            return apology("Invalide type, must be png , jpg ,jpeg .", 400)

        # save the uploded file

        filename = secure_filename(img.filename)
        img.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        img_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        Category = int(Category)
        stock = int(stock)
        Price = float(Price)
        promo = float(promo)
        db.execute(
            """
            UPDATE products SET name = ?,description = ?,img_url = ?,price_unit = ?,promo = ?,category_id = ?,stock = ?
            WHERE P_id = ?
            """,
            product_name,
            Description,
            img_path,
            Price,
            promo,
            Category,
            stock,
            product_id,
        )
        return redirect("/admindashbord")

    Products = db.execute(
        """
        SELECT * FROM products
        WHERE P_id = ?
        """,
        product_id,
    )

    Categorys = db.execute(
        """
        SELECT * FROM category
        """
    )
    Products = Products[0]
    return render_template("edit.html", product=Products, Categorys=Categorys)


@app.route("/admindashbord")
@login_required
@admin_required
def admin_dashboard():
    user_id = session["user_id"]
    users = db.execute(
        """
        SELECT * from users
        WHERE users.id = ?
        """,
        user_id,
    )

    if users[0]["role"] != "Admin":
        flash("You're not an admin")
        return redirect("/login")
    users = db.execute(
        """
        SELECT * from users
        WHERE users.id = ?
        """,
        user_id,
    )

    if users[0]["role"] != "Admin":
        flash("You're not an admin")
        return redirect("/login")
    Products = db.execute(
        """
        SELECT * FROM products
        """
    )

    Categorys = db.execute(
        """
        SELECT * FROM category
        """
    )
    return render_template("adminporduct.html", Products=Products, Categorys=Categorys)


@app.route("/category/<int:id>", methods=["GET"])
def category(id):
    p_id = id
    admin = False
    # id validation
    if p_id < 1 or p_id > 5:
        flash("invalid category")
        return redirect("/")

    prods = db.execute(
        """
        SELECT * FROM products
        INNER JOIN category ON products.category_id = category.id
        WHERE products.category_id = ?
        """,
        p_id,
    )
    Categorys = db.execute(
        """
            SELECT * FROM category
            """
    )
    if "user_id" in session and session["user_id"] == 1:
        admin = True
    category = prods[0]["category"]
    return render_template(
        "category.html",
        prods=prods,
        category=category,
        Categorys=Categorys,
        admin=admin,
    )


@app.route("/promo")
def promo():
    # get products with promo greater than 0
    admin = False
    Products = db.execute(
        """
            SELECT * FROM products
            WHERE products.promo > 0
            """
    )
    Categorys = db.execute(
        """
            SELECT * FROM category
            """
    )
    if "user_id" in session and session["user_id"] == 1:
        admin = True
    return render_template(
        "promo.html", Products=Products, Categorys=Categorys, admin=admin
    )


@app.route("/", methods=["GET"])
def home():
    # home show products
    admin = False
    Products = db.execute(
        """
        SELECT * FROM products
        """
    )
    Categorys = db.execute(
        """
        SELECT * FROM category
        """
    )
    if "user_id" in session and session["user_id"] == 1:
        admin = True
    return render_template(
        "home.html", Products=Products, Categorys=Categorys, admin=admin
    )


@app.route("/logAdmin", methods=["GET", "POST"])
def logAdmin():
    """Log user in"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            message = flash("must provide username", "error")
            return render_template("logAdmin.html", message=message)

        # Ensure password was submitted
        if not request.form.get("password"):
            message = flash("must provide password", "error")
            return render_template("logAdmin.html", message=message)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE name = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["password"], request.form.get("password")
        ):
            message = flash("invalid username and/or password" "error")
            return render_template("logAdmin.html", message=message)

        if rows[0]["secret_key"] != request.form.get("secretkey"):
            message = flash(" invalid  secretkey ")
            return render_template("login.html", message=message)

        if rows[0]["role"] != "Admin":
            return apology("Your are not admin", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/admindashbord")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("logAdmin.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            message = flash("must provide username", "error")
            return render_template("login.html", message=message)

        # Ensure password was submitted
        if not request.form.get("password"):
            message = flash("must provide password", "error")
            return render_template("login.html", message=message)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE name = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["password"], request.form.get("password")
        ):
            message = flash("invalid username and/or password" "error")
            return render_template("login.html", message=message)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/new_password/<int:id>", methods=["GET", "POST"])
def new_password(id):
    user_id = id
    print(user_id)
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # store the user's new password into variable
        password = request.form.get("password")

        # store the user's passwordConfirmation into variable
        passwordConfirmation = request.form.get("confirmation")

        # check the user's password not empty
        if not password:
            message = flash("must provide password")
            return render_template(
                "new_password.html", message=message, user_id=user_id
            )
        # check the user's password lenght
        if len(password) < 8:
            message = flash("the password's lenght must be greater then 8 characters ")
            return render_template(
                "new_password.html", message=message, user_id=user_id
            )
        # check the user's password include characters
        if isAllPassword_Digite(password):
            message = flash("the password's must include characters")
            return render_template(
                "new_password.html", message=message, user_id=user_id
            )
        # check the user's passwordConfirmation not empty
        if not passwordConfirmation:
            message = flash("must provide passwordConfirmation")
            return render_template(
                "new_password.html", message=message, user_id=user_id
            )
        # check the user's passwordConfirmation and password are mached
        if passwordConfirmation != password:
            message = flash("the password arn't mached")
            return render_template(
                "new_password.html", message=message, user_id=user_id
            )
        hash_password = generate_password_hash(password)
        db.execute(
            """
            UPDATE users SET password = ?
            WHERE users.id=?
            """,
            hash_password,
            user_id,
        )
        # Redirect user to login page
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("new_password.html", user_id=user_id)


@app.route("/wallet", methods=["GET", "POST"])
@login_required
def addcash():
    user_id = session["user_id"]
    admin = False
    user = db.execute(
        """
            SELECT * FROM users
            WHERE id = ?
            """,
        user_id,
    )

    Categorys = db.execute(
        """
        SELECT * FROM category
        """
    )
    user = user[0]
    if request.method == "GET":
        if "user_id" in session and session["user_id"] == 1:
            admin = True
        return render_template(
            "wallet.html", user=user, Categorys=Categorys, admin=admin
        )
    else:
        cash = request.form.get("cash")
        cash = float(cash)
        if cash == 0:
            message = flash("You can't add 0DH! amount must be greater then 100DH")
            return render_template(
                "wallet.html", user=user, message=message, Categorys=Categorys
            )

        if cash < 100:
            message = flash("amount must be greater then 100DH")
            return render_template(
                "wallet.html", user=user, message=message, Categorys=Categorys
            )

        else:
            db.execute(
                """
                    UPDATE users SET cash = cash + ?
                    WHERE users.id = ?
                    """,
                cash,
                user_id,
            )
            message = flash("amount added seccefuly")
            if "user_id" in session and session["user_id"] == 1:
                admin = True
            return redirect("/wallet")


@app.route("/pay/<int:id>", methods=["GET", "POST"])
@login_required
def pay(id):
    if "user_id" not in session:
        return redirect("/login")
    Tot_Bill = db.execute(
        """
                SELECT 	SUM (( (products.price_unit * (1 - products.promo)) * cart.quantity )) as TOT_bill,
                users.cash as Your_Cash,
                users.cash_bonus FROM cart
                JOIN users on users.id = cart.user_id
                JOIN products ON products.P_id = cart.pord_id
                WHERE cart.user_id = ?;
                """,
        id,
    )

    user = db.execute(
        """
            SELECT * FROM users
            WHERE id = ?
            """,
        id,
    )
    name = user[0]["name"]
    cash = user[0]["cash"]
    print(name)
    Tot_Bill = Tot_Bill[0]
    Categorys = db.execute(
        """
            SELECT * FROM category
            """
    )

    if request.method == "GET":
        return render_template(
            "validation.html",
            Categorys=Categorys,
            user_id=id,
            Tot_Bill=Tot_Bill,
        )
    if request.method == "POST":
        # je peut prender le facture total
        facture = float(request.form.get("tot"))
        bonus_cash_useed = float(request.form.get("range"))

        facture = Tot_Bill['TOT_bill']
        print(bonus_cash_useed)
        print(cash)
        if cash > facture :
            print(name + " can buy")

            current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            PorductsInCart = db.execute(
                """
                SELECT * FROM cart
                JOIN users ON users.id = cart.user_id
                JOIN products ON products.P_id = cart.pord_id
                WHERE cart.user_id = ?;
            """,
                id,
            )

            for prod in PorductsInCart:
                db.execute(
                    """
                    UPDATE products
                    SET stock = products.stock - ?
                    WHERE P_id = ?;
                """,
                    prod["quantity"],
                    prod["pord_id"],
                )


            #todo if users use bounus cash
            db.execute(
                """
                UPDATE users set cash = cash - ? ,
                cash_bonus = cash_bonus - ? + ?
                where id = ?
                """,
                facture,
                bonus_cash_useed,
                facture * 0.03,
                id
            )
            db.execute(
                """
                DELETE  FROM cart
                where user_id = ?
                """,
                id
            )

            return render_template(
                "facture.html",
                PorductsInCart=PorductsInCart,
                Categorys=Categorys,
                Tot_Bill=Tot_Bill,
                user_id=id,
                name=name,
                bonus_cash_useed=bonus_cash_useed,
                current_date=current_date,
            )

        else :
            message = flash("you donèt have enought monney")
            return render_template(
            "validation.html",
            Categorys=Categorys,
            user_id=id,
            Tot_Bill=Tot_Bill,
            message=message,
        )


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    user_id = session["user_id"]
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # store the user's new password into variable
        oldpassword = request.form.get("oldpassword")

        password = request.form.get("password")

        # store the user's passwordConfirmation into variable
        passwordConfirmation = request.form.get("confirmation")

        # check the user's password not empty
        if not oldpassword:
            message = flash("must provide oldpassword")
            return render_template(
                "chnage_password.html", message=message, user_id=user_id
            )

        if not password:
            message = flash("must provide password")
            return render_template(
                "chnage_password.html", message=message, user_id=user_id
            )

        # check the user's password lenght
        if len(password) < 8:
            message = flash("the password's lenght must be greater then 8 characters ")
            return render_template(
                "chnage_password.html", message=message, user_id=user_id
            )

        # check the user's password include characters
        if isAllPassword_Digite(password):
            message = flash("the password's must include characters")
            return render_template(
                "chnage_password.html", message=message, user_id=user_id
            )

        # check the user's passwordConfirmation not empty
        if not passwordConfirmation:
            message = flash("must provide passwordConfirmation")
            return render_template(
                "chnage_password.html", message=message, user_id=user_id
            )

        # check the user's passwordConfirmation and password are mached
        if passwordConfirmation != password:
            message = flash("the password arn't mached")
            return render_template(
                "chnage_password.html", message=message, user_id=user_id
            )

        rows = db.execute(
            "SELECT * FROM users WHERE id = ?",
            user_id,
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], oldpassword):
            message = flash("invalid or password", "error")
            return render_template("chnage_password.html", message=message)

        hash_password = generate_password_hash(password)
        db.execute(
            """
            UPDATE users SET password = ?
            WHERE users.id=?
            """,
            hash_password,
            user_id,
        )
        # home show products
        Products = db.execute(
            """
            SELECT * FROM products
            """
        )
        Categorys = db.execute(
            """
            SELECT * FROM category
            """
        )
        message = flash("password has changed successfully")
        # Redirect user to login page
        return render_template(
            "home.html", message=message, Categorys=Categorys, Products=Products
        )

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("change_password.html", user_id=user_id)


@app.route("/forgetPassword", methods=["GET", "POST"])
def forget_password():
    """Log user in"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            message = flash("must provide username", "error")
            return render_template("forget_password.html", message=message)

        # Ensure password was submitted
        if not request.form.get("secretkey"):
            message = flash("must provide secretkey", "error")
            return render_template("forget_password.html", message=message)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE name = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1:
            message = flash("invalid username ", "error")
            return render_template("forget_password.html", message=message)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        user_id = session["user_id"]
        # Redirect user to home page
        return redirect(f"/new_password/{user_id}")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("forget_password.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)

    if request.method == "POST":
        # store the user's username into variable
        username = request.form.get("username")

        # store the user's password into variable
        password = request.form.get("password")

        # store the user's passwordConfirmation into variable
        passwordConfirmation = request.form.get("confirmation")
        secret_Key = request.form.get("secret_key")

        # check the user's username not empty
        if not username:
            return apology("must provide username", 400)

        # check the user's username not already exists
        if isUsernameAlreadyExiste(username):
            return apology(
                "username already exists! must provide another username", 400
            )

        # check the user's password not empty
        if not password:
            return apology("must provide password", 400)

        # check the user's secret_key not empty
        if not secret_Key:
            return apology("must provide secret_Key", 400)

        # check the user's password lenght
        if len(password) < 8:
            return apology(
                "the password's lenght must be greater then 8 characters ", 400
            )

        # check the user's password include characters
        if isAllPassword_Digite(password):
            return apology("the password's must include characters", 400)

        # check the user's passwordConfirmation not empty
        if not passwordConfirmation:
            return apology("must provide passwordConfirmation", 400)

        # check the user's passwordConfirmation and password are mached
        if passwordConfirmation != password:
            return apology("the password arn't mached", 400)

        hash_password = generate_password_hash(password)
        db.execute(
            """
            INSERT INTO users (name,password,secret_key,role,cash) VALUES (?,?,?,?,?)
             """,
            username,
            hash_password,
            secret_Key,
            "Client",
            5000,
        )

        # login The user

        rows = db.execute(
            """
                            SELECT * FROM users
                            WHERE users.name = ?
            """,
            username,
        )

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        return redirect("/")
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to home
    return redirect("/")
