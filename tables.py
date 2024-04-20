from cs50 import SQL

db = SQL("sqlite:///project.db")

# Create a 'users' table
db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        password TEXT NOT NULL,
        secret_key TEXT NOT NULL,
        role TEXT NOT NULL,
        cash REAL NOT NULL DEFAULT 0,
        cash_bonus REAL NOT NULL DEFAULT 0
    )
""")

# Create a 'products' table
db.execute("""
    CREATE TABLE IF NOT EXISTS products (
        P_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        img_url TEXT NOT NULL,
        price_unit REAL NOT NULL DEFAULT 0,
        promo REAL NOT NULL DEFAULT 0,
        category_id INTEGER NOT NULL,
        stock INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (category_id) REFERENCES category(id)
    )
""")

# Create a 'category' table
db.execute("""
    CREATE TABLE IF NOT EXISTS category (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL
    )
""")

# Create a 'fav_prod' table
db.execute("""
    CREATE TABLE IF NOT EXISTS fav_prod (
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL
    )
""")
