import os
import bcrypt
import jwt
import datetime
import requests
import certifi
import uuid
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_from_directory, abort
from flask_cors import CORS
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from dotenv import load_dotenv
from bson.objectid import ObjectId
from bson.errors import InvalidId

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
    """Check if the uploaded file has an allowed extension."""
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
# HELPER FUNCTIONS
# ==========================
def safe_objectid(id_str):
    """Convert a string to ObjectId safely. Return None if invalid."""
    try:
        return ObjectId(id_str)
    except (InvalidId, TypeError):
        return None

def convert_doc(doc):
    """Convert a MongoDB document to a JSON‑friendly dict (ObjectId → str)."""
    if not doc:
        return doc
    doc["_id"] = str(doc["_id"])
    return doc

def convert_cursor(cursor):
    """Convert a cursor of MongoDB documents to a list of JSON‑friendly dicts."""
    return [convert_doc(doc) for doc in cursor]

def validate_product_data(name, price, stock, length, category):
    """Validate common product fields. Return (is_valid, error_message)."""
    if not name or not name.strip():
        return False, "Product name is required."
    try:
        price_val = float(price)
        if price_val < 0:
            return False, "Price cannot be negative."
    except (ValueError, TypeError):
        return False, "Price must be a valid number."

    try:
        stock_val = int(stock)
        if stock_val < 0:
            return False, "Stock cannot be negative."
    except (ValueError, TypeError):
        return False, "Stock must be a valid integer."

    try:
        length_val = int(length)
        if length_val < 0:
            return False, "Length cannot be negative."
    except (ValueError, TypeError):
        return False, "Length must be a valid integer."

    if not category or not category.strip():
        return False, "Category is required."

    return True, ""

# ==========================
# AUTH DECORATOR
# ==========================
def token_required(f):
    """Decorator to protect admin routes. Extracts JWT from cookie and loads current admin."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("admin_token")
        if not token:
            flash("Please log in to access the admin area.")
            return redirect(url_for("admin_login_page"))

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            admin_id = safe_objectid(data.get("id"))
            if not admin_id:
                raise InvalidId
            current_admin = admins_collection.find_one({"_id": admin_id})
            if not current_admin:
                flash("Admin account not found.")
                return redirect(url_for("admin_login_page"))
        except (jwt.InvalidTokenError, InvalidId, Exception):
            flash("Invalid or expired session. Please log in again.")
            return redirect(url_for("admin_login_page"))

        return f(current_admin, *args, **kwargs)
    return decorated

# ==========================
# PUBLIC ROUTES (PAGES)
# ==========================
@app.route("/")
def home():
    products = convert_cursor(products_collection.find())
    return render_template("home.html", products=products)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/collection")
def collection():
    return redirect(url_for("shop"))

@app.route("/shop")
def shop():
    products = convert_cursor(products_collection.find())
    return render_template("shop.html", products=products)

@app.route("/cart")
def cart():
    return render_template("cart.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/product/<product_id>")
def product_detail(product_id):
    obj_id = safe_objectid(product_id)
    if not obj_id:
        abort(404, description="Invalid product ID format.")
    
    product = products_collection.find_one({"_id": obj_id})
    if not product:
        abort(404, description="Product not found.")
    
    product = convert_doc(product)
    product["id"] = product["_id"]   # convenience for templates
    
    # Fetch related products (same category, excluding current, limit 4)
    related_products = []
    if product.get("category"):
        related_cursor = products_collection.find({
            "_id": {"$ne": obj_id},
            "category": product["category"]
        }).limit(4)
        related_products = convert_cursor(related_cursor)
    
    return render_template("product.html", product=product, related_products=related_products)

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

    # Verify with Paystack
    try:
        response = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers={"Authorization": f"Bearer {PAYSTACK_SECRET}"}
        )
        result = response.json()
    except Exception as e:
        return jsonify({"message": "Paystack verification failed", "error": str(e)}), 500

    if result.get("status") and result["data"]["status"] == "success":
        # Validate stock before updating (prevent negative stock)
        items = order_data.get("items", [])
        stock_errors = []
        for item in items:
            product_id = item.get("productId")
            quantity = item.get("quantity", 1)
            obj_id = safe_objectid(product_id)
            if not obj_id:
                stock_errors.append(f"Invalid product ID: {product_id}")
                continue
            product = products_collection.find_one({"_id": obj_id})
            if not product:
                stock_errors.append(f"Product not found: {product_id}")
                continue
            current_stock = product.get("stock", 0)
            if current_stock < quantity:
                stock_errors.append(
                    f"Insufficient stock for {product.get('name', product_id)}. "
                    f"Available: {current_stock}, requested: {quantity}"
                )
        if stock_errors:
            return jsonify({"message": "Stock validation failed", "errors": stock_errors}), 400

        # All good – update stock and save order
        for item in items:
            product_id = item.get("productId")
            quantity = item.get("quantity", 1)
            obj_id = safe_objectid(product_id)
            if obj_id:
                products_collection.update_one(
                    {"_id": obj_id},
                    {"$inc": {"stock": -quantity}}
                )

        order_data["paymentReference"] = reference
        order_data["status"] = "Pending"
        order_data["createdAt"] = datetime.datetime.utcnow()
        order_data["paidAt"] = datetime.datetime.utcnow()
        orders_collection.insert_one(order_data)

        return jsonify({"message": "Payment verified and order saved", "reference": reference})

    return jsonify({"message": "Payment verification failed", "details": result}), 400

@app.route("/order/<reference>")
def order_status(reference):
    order = orders_collection.find_one({"paymentReference": reference})
    if not order:
        abort(404, description="Order not found.")
    order = convert_doc(order)
    return render_template("order_status.html", order=order)

# ==========================
# ADMIN ROUTES
# ==========================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login_page():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        admin = admins_collection.find_one({"email": email})
        if not admin:
            flash("Invalid email or password.")
            return redirect(url_for("admin_login_page"))

        if not bcrypt.checkpw(password.encode(), admin["password"]):
            flash("Invalid email or password.")
            return redirect(url_for("admin_login_page"))

        token = jwt.encode(
            {
                "id": str(admin["_id"]),
                "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
            },
            JWT_SECRET,
            algorithm="HS256"
        )

        response = redirect(url_for("admin_dashboard"))
        # Secure cookie flags
        response.set_cookie(
            "admin_token",
            token,
            httponly=True,
            secure=os.getenv("FLASK_ENV") == "production",  # only secure in production
            samesite="Lax"
        )
        flash("Login successful.")
        return response

    return render_template("admin_login.html")

@app.route("/admin/dashboard")
@token_required
def admin_dashboard(current_admin):
    products = convert_cursor(products_collection.find())
    orders = convert_cursor(orders_collection.find())
    return render_template("admin.html", products=products, orders=orders)

@app.route("/admin/register", methods=["GET", "POST"])
@token_required
def admin_register(current_admin):
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

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

@app.route("/admin/edit-product/<product_id>", methods=["GET", "POST"])
@token_required
def edit_product(current_admin, product_id):
    obj_id = safe_objectid(product_id)
    if not obj_id:
        flash("Invalid product ID.")
        return redirect(url_for("admin_dashboard"))

    product = products_collection.find_one({"_id": obj_id})
    if not product:
        flash("Product not found.")
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price = request.form.get("price")
        category = request.form.get("category", "").strip()
        length = request.form.get("length")
        stock = request.form.get("stock")
        description = request.form.get("description", "").strip()

        is_valid, error_msg = validate_product_data(name, price, stock, length, category)
        if not is_valid:
            flash(error_msg)
            return redirect(url_for("edit_product", product_id=product_id))

        # Additional: prevent negative stock during edit already handled by validator
        products_collection.update_one(
            {"_id": obj_id},
            {"$set": {
                "name": name,
                "price": float(price),
                "category": category,
                "length": int(length),
                "stock": int(stock),
                "description": description
            }}
        )
        flash("Product updated successfully.")
        return redirect(url_for("admin_dashboard"))

    product = convert_doc(product)
    return render_template("edit_product.html", product=product)

@app.route("/admin/add-product", methods=["POST"])
@token_required
def add_product(current_admin):
    # Validate required fields
    name = request.form.get("name", "").strip()
    price = request.form.get("price")
    description = request.form.get("description", "").strip()
    stock = request.form.get("stock")
    category = request.form.get("category", "").strip()
    length = request.form.get("length")

    is_valid, error_msg = validate_product_data(name, price, stock, length, category)
    if not is_valid:
        flash(error_msg)
        return redirect(url_for("admin_dashboard"))

    # Handle file upload
    if 'image' not in request.files:
        flash("No image file provided.")
        return redirect(url_for("admin_dashboard"))

    file = request.files['image']
    if file.filename == '':
        flash("No selected file.")
        return redirect(url_for("admin_dashboard"))

    if not allowed_file(file.filename):
        flash("Invalid file type. Allowed: png, jpg, jpeg, gif, webp.")
        return redirect(url_for("admin_dashboard"))

    # Secure filename with UUID to prevent collisions
    original_filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4().hex}_{original_filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(file_path)
    image_url = url_for('static', filename='uploads/' + unique_filename)

    # Insert product
    product_data = {
        "name": name,
        "price": float(price),
        "image": image_url,
        "description": description,
        "stock": int(stock),
        "category": category,
        "length": int(length)
    }
    products_collection.insert_one(product_data)
    flash("Product added successfully.")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/delete-product/<product_id>")
@token_required
def delete_product(current_admin, product_id):
    obj_id = safe_objectid(product_id)
    if not obj_id:
        flash("Invalid product ID.")
        return redirect(url_for("admin_dashboard"))

    result = products_collection.delete_one({"_id": obj_id})
    if result.deleted_count == 0:
        flash("Product not found.")
    else:
        flash("Product deleted successfully.")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/update-order/<reference>", methods=["POST"])
@token_required
def update_order(current_admin, reference):
    new_status = request.form.get("status")
    if not new_status:
        flash("Status is required.")
        return redirect(url_for("admin_dashboard"))

    result = orders_collection.update_one(
        {"paymentReference": reference},
        {"$set": {"status": new_status}}
    )
    if result.matched_count == 0:
        flash("Order not found.")
    else:
        flash("Order status updated.")
    return redirect(url_for("admin_dashboard"))

# ==========================
# SERVE UPLOADED FILES
# ==========================
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ==========================
# ERROR HANDLERS
# ==========================
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500

# ==========================
# RUN SERVER
# ==========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
