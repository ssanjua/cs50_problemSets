import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    # Obtiene el ID del usuario actual
    user_id = session["user_id"]

    # Obtiene las acciones y el número de acciones del usuario
    rows = db.execute(
        "SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0",
        user_id,
    )

    # Obtiene el efectivo del usuario
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    # Lista para almacenar la información de cada acción
    holdings = []
    total_portfolio_value = cash  # Comienza con el efectivo del usuario

    # Para cada acción, obtén el precio actual y calcula el valor total
    for row in rows:
        stock = lookup(row["symbol"])
        holdings.append(
            {
                "symbol": row["symbol"],
                "name": stock["name"],  # Nombre de la empresa
                "shares": row["total_shares"],
                "price": stock["price"],  # Precio actual por acción
                "total": row["total_shares"]
                * stock["price"],  # Valor total de las acciones
            }
        )
        total_portfolio_value += row["total_shares"] * stock["price"]

    # Renderiza index.html pasando la información del portafolio y el efectivo
    return render_template(
        "index.html", holdings=holdings, cash=cash, total=total_portfolio_value
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Shares must be a positive integer", 400)

        if shares <= 0:
            return apology("Can't buy a non-positive number of shares", 400)

    if request.method == "POST":
        # Obtener los datos del formulario
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # Verificar símbolo válido
        stock = lookup(symbol)
        if stock is None:
            return apology("Invalid symbol", 400)

        # Verificar cantidad válida
        if shares <= 0:
            return apology("Must buy at least 1 share", 400)

        # Verificar si el usuario tiene suficiente dinero
        rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = rows[0]["cash"]
        cost = stock["price"] * shares
        if cash < cost:
            return apology("Not enough money", 403)

        # Actualizar base de datos y redirigir
        db.execute(
            "UPDATE users SET cash = cash - ? WHERE id = ?", cost, session["user_id"]
        )
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, timestamp) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
            session["user_id"],
            symbol,
            shares,
            stock["price"],
        )
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    # Obtener todas las transacciones del usuario de la base de datos
    transactions = db.execute(
        "SELECT timestamp, symbol, shares, price FROM transactions WHERE user_id = ? ORDER BY timestamp DESC",
        session["user_id"],
    )

    # Inferir el tipo de transacción y formatear para visualización
    for transaction in transactions:
        transaction["type"] = "BUY" if transaction["shares"] > 0 else "SELL"
        transaction["shares"] = abs(transaction["shares"])

    # Renderizar la plantilla de historial pasando las transacciones
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    # Si el usuario llega vía GET, muestra el formulario
    if request.method == "GET":
        return render_template("quote.html")

    # Si el usuario llega vía POST, procesa el formulario
    else:
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Must provide symbol", 400)

        quote = lookup(symbol)
        if quote is None:
            return apology("Invalid symbol", 400)

        # Muestra la plantilla con el precio de la acción
        return render_template("quoted.html", quote=quote)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Obten los datos del formulario
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Verifica si el nombre de usuario existe
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) > 0:
            return apology("Username already exists", 400)

        # Verifica si las contraseñas coinciden
        if password != confirmation:
            return apology("Passwords do not match", 400)

        # cada campo se haya rellenado
        if not username or not password or not confirmation:
            return apology("All fields must be completed", 400)

        # Inserta el nuevo usuario en la base de datos
        hash_password = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)", username, hash_password
        )

        # Redirige al usuario a la página de inicio
        return redirect("/")

    # Si el usuario llega vía GET (o cualquier otro método)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Shares must be an integer", 400)

        if shares <= 0:
            return apology("Can't sell a non-positive number of shares", 400)

        # Aquí comprobarías si el usuario tiene suficientes acciones para vender
        user_shares = db.execute("SELECT shares FROM ... WHERE ...")
        if shares > user_shares:
            return apology("Can't sell more shares than you own", 400)

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares_to_sell = int(request.form.get("shares"))

        if not symbol:
            return apology("Must select a stock", 403)

        if shares_to_sell <= 0:
            return apology("Must sell at least one share", 403)

        # Verifica cuántas acciones tiene el usuario
        shares_owned = db.execute(
            "SELECT SUM(shares) as total_shares FROM transactions WHERE user_id = ? AND symbol = ?",
            session["user_id"],
            symbol,
        )[0]["total_shares"]

        if shares_owned is None or shares_to_sell > shares_owned:
            return apology("Not enough shares", 403)

        # Obtiene el precio actual de la acción
        stock = lookup(symbol)

        # Actualiza la base de datos para reflejar la venta
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, timestamp) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
            session["user_id"],
            symbol,
            -shares_to_sell,
            stock["price"],
        )

        # Actualiza el saldo en efectivo del usuario
        db.execute(
            "UPDATE users SET cash = cash + ? WHERE id = ?",
            stock["price"] * shares_to_sell,
            session["user_id"],
        )

        return redirect("/")
    else:
        # Obtiene las acciones que posee el usuario para el menú desplegable
        stocks = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0",
            session["user_id"],
        )
        return render_template("sell.html", stocks=stocks)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        user_id = session["user_id"]
        user_info = db.execute("SELECT * FROM users WHERE id = ?", user_id)

        # Verifica la contraseña actual
        if not check_password_hash(user_info[0]["hash"], old_password):
            return apology("Invalid current password", 403)

        # Verifica que las nuevas contraseñas coincidan
        if new_password != confirmation:
            return apology("New passwords do not match", 403)

        # Actualiza la contraseña
        hash_password = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hash_password, user_id)

        flash("Password changed successfully!")
        return redirect("/")

    else:
        return render_template("change_password.html")
