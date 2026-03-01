import os
import bcrypt
import jwt
import datetime
import requests
import certifi
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from dotenv import load_dotenv
from bson.objectid import ObjectId

load_dotenv()

app = Flask(__name__)
CORS(app)

app.secret_key = os.getenv("JWT_SECRET")

# ==========================
# ENV VARIABLES
# ==========================
MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET = os.getenv("JWT_SECRET")
PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET")
PAYSTACK_PUBLIC_KEY = os.getenv("PAYSTACK_PUBLIC_KEY")

# ==========================
# FILE UPLOAD CONFIGURATION
# ==========================
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ==========================
# DATABASE
# ==========================
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client["kikky"]
products_collection = db["products"]
orders_collection = db["orders"]
admins_collection = db["admins"]

# ==========================
# AUTH DECORATOR
# ==========================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("admin_token")
        if not token:
            return redirect(url_for("admin_login_page"))

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            current_admin = admins_collection.find_one({"_id": ObjectId(data["id"])})
            if not current_admin:
                return redirect(url_for("admin_login_page"))
        except:
            return redirect(url_for("admin_login_page"))

        return f(current_admin, *args, **kwargs)
    return decorated

# ==========================
# PUBLIC ROUTES (PAGES)
# ==========================
@app.route("/")
def home():
    products = list(products_collection.find())
    for product in products:
        product['_id'] = str(product['_id'])
    return render_template("home.html", products=products)

@app.route("/collection")
def collection():
    products = list(products_collection.find())
    for product in products:
        product['_id'] = str(product['_id'])
    return render_template("collection.html", products=products)

@app.route("/shop")
def shop():
    products = list(products_collection.find())
    for product in products:
        product['_id'] = str(product['_id'])
    return render_template("shop.html", products=products)

@app.route("/cart")
def cart():
    return render_template("cart.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

# ==========================
# CHECKOUT & PAYMENT ROUTES
# ==========================
@app.route("/checkout")
def checkout():
    return render_template("checkout.html", public_key=PAYSTACK_PUBLIC_KEY)

@app.route("/verify-payment", methods=["POST"])
def verify_payment():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid request"}), 400

    reference = data.get("reference")
    order_data = data.get("orderData", {})

    if not reference or not order_data:
        return jsonify({"message": "Missing reference or order data"}), 400

    try:
        response = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers={"Authorization": f"Bearer {PAYSTACK_SECRET}"}
        )
        result = response.json()
    except Exception as e:
        return jsonify({"message": "Paystack verification failed", "error": str(e)}), 500

    if result.get("status") and result["data"]["status"] == "success":
        order_data["paymentReference"] = reference
        order_data["status"] = "Pending"
        order_data["createdAt"] = datetime.datetime.utcnow()
        order_data["paidAt"] = datetime.datetime.utcnow()

        for item in order_data.get("items", []):
            product_id = item.get("productId")
            quantity = item.get("quantity", 1)
            products_collection.update_one(
                {"_id": ObjectId(product_id)},
                {"$inc": {"stock": -quantity}}
            )

        orders_collection.insert_one(order_data)
        return jsonify({"message": "Payment verified and order saved", "reference": reference})

    return jsonify({"message": "Payment verification failed", "details": result}), 400

@app.route("/order/<reference>")
def order_status(reference):
    order = orders_collection.find_one({"paymentReference": reference})
    if not order:
        return "Order not found", 404
    return render_template("order_status.html", order=order)

# ==========================
# ADMIN ROUTES
# ==========================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login_page():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        admin = admins_collection.find_one({"email": email})
        if not admin:
            return "Admin not found"

        if not bcrypt.checkpw(password.encode(), admin["password"]):
            return "Wrong password"

        token = jwt.encode(
            {
                "id": str(admin["_id"]),
                "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
            },
            JWT_SECRET,
            algorithm="HS256"
        )

        response = redirect(url_for("admin_dashboard"))
        response.set_cookie("admin_token", token)
        return response

    return render_template("admin_login.html")

@app.route("/admin/dashboard")
@token_required
def admin_dashboard(current_admin):
    products = list(products_collection.find())
    orders = list(orders_collection.find())
    return render_template("admin.html", products=products, orders=orders)

@app.route("/admin/register", methods=["GET", "POST"])
@token_required
def admin_register(current_admin):
    if request.method == "POST":
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")

        if not email or not password:
            flash("Email and password are required.")
            return redirect(url_for("admin_register"))

        if password != confirm:
            flash("Passwords do not match.")
            return redirect(url_for("admin_register"))

        if admins_collection.find_one({"email": email}):
            flash("An admin with that email already exists.")
            return redirect(url_for("admin_register"))

        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        admins_collection.insert_one({
            "email": email,
            "password": hashed,
            "created_by": current_admin["email"],
            "role": "admin"
        })

        flash("New admin created successfully!")
        return redirect(url_for("admin_dashboard"))

    return render_template("admin_register.html")

# ==========================
# ADMIN PRODUCT MANAGEMENT (with file upload and category/length)
# ==========================
@app.route("/admin/add-product", methods=["POST"])
@token_required
def add_product(current_admin):
    if 'image' not in request.files:
        flash("No image file provided")
        return redirect(url_for("admin_dashboard"))
    
    file = request.files['image']
    if file.filename == '':
        flash("No selected file")
        return redirect(url_for("admin_dashboard"))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{datetime.datetime.utcnow().timestamp()}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        image_url = url_for('static', filename='uploads/' + unique_filename)
    else:
        flash("Invalid file type. Allowed: png, jpg, jpeg, gif, webp")
        return redirect(url_for("admin_dashboard"))
    
    name = request.form.get("name")
    price = float(request.form.get("price"))
    description = request.form.get("description")
    stock = int(request.form.get("stock"))
    category = request.form.get("category")
    length = request.form.get("length")
    
    if not category or not length:
        flash("Category and length are required")
        return redirect(url_for("admin_dashboard"))
    
    data = {
        "name": name,
        "price": price,
        "image": image_url,
        "description": description,
        "stock": stock,
        "category": category,
        "length": int(length)
    }
    products_collection.insert_one(data)
    
    flash("Product added successfully")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/delete-product/<product_id>")
@token_required
def delete_product(current_admin, product_id):
    products_collection.delete_one({"_id": ObjectId(product_id)})
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/update-order/<reference>", methods=["POST"])
@token_required
def update_order(current_admin, reference):
    new_status = request.form.get("status")
    orders_collection.update_one(
        {"paymentReference": reference},
        {"$set": {"status": new_status}}
    )
    return redirect(url_for("admin_dashboard"))

# ==========================
# SERVE UPLOADED FILES
# ==========================
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ==========================
# RUN SERVER
# ==========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
