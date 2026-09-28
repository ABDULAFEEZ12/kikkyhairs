import os
import re
import io
import hmac
import hashlib
import secrets
import bcrypt
import jwt
import datetime
import certifi
import threading
import requests
from collections import OrderedDict
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, abort, Response
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
from bson.objectid import ObjectId
from bson.errors import InvalidId
from gridfs import GridFSBucket
from gridfs.errors import NoFile
from PIL import Image, ImageOps

load_dotenv()

app = Flask(__name__)
CORS(app)

app.secret_key = os.getenv("JWT_SECRET")

# ==========================
# ENV VARIABLES
# ==========================
MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET = os.getenv("JWT_SECRET")

# ==========================
# SQUAD PAYMENT GATEWAY
# ==========================
SQUAD_SECRET_KEY = os.getenv("SQUAD_SECRET_KEY")
SQUAD_PUBLIC_KEY = os.getenv("SQUAD_PUBLIC_KEY")
SQUAD_IS_SANDBOX = bool(SQUAD_SECRET_KEY) and SQUAD_SECRET_KEY.startswith("sandbox_sk_")
SQUAD_BASE_URL = (
    "https://sandbox-api-d.squadco.com" if SQUAD_IS_SANDBOX
    else "https://api-d.squadco.com"
)

# ==========================
# FILE UPLOAD CONFIGURATION
# ==========================
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ==========================
# DATABASE
# ==========================
client = MongoClient(
    MONGO_URI,
    tlsCAFile=certifi.where(),
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=5000,
    socketTimeoutMS=15000,
    maxPoolSize=20
)
db = client["kikky"]
products_collection = db["products"]
orders_collection = db["orders"]
admins_collection = db["admins"]
messages_collection = db["messages"]
fs_bucket = GridFSBucket(db)

IMAGE_MAX_DIMENSION = 1200
IMAGE_JPEG_QUALITY = 80

def compress_image(raw_bytes, fallback_content_type):
    """Resize/compress an image for fast web delivery. Falls back to the
    original bytes untouched if Pillow can't decode the file for any reason."""
    try:
        img = Image.open(io.BytesIO(raw_bytes))
        img = ImageOps.exif_transpose(img)

        if img.width > IMAGE_MAX_DIMENSION or img.height > IMAGE_MAX_DIMENSION:
            img.thumbnail((IMAGE_MAX_DIMENSION, IMAGE_MAX_DIMENSION), Image.LANCZOS)

        has_alpha = img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info)
        buf = io.BytesIO()
        if has_alpha:
            img.convert("RGBA").save(buf, format="PNG", optimize=True)
            content_type = "image/png"
        else:
            img.convert("RGB").save(buf, format="JPEG", quality=IMAGE_JPEG_QUALITY, optimize=True)
            content_type = "image/jpeg"

        compressed = buf.getvalue()
        if len(compressed) < len(raw_bytes):
            return compressed, content_type
        return raw_bytes, fallback_content_type
    except Exception:
        return raw_bytes, fallback_content_type

def upload_to_gridfs(file):
    """Compress the image, then upload it to GridFS and return a servable URL path."""
    raw_bytes = file.read()
    data, content_type = compress_image(raw_bytes, file.mimetype)
    file_id = fs_bucket.upload_from_stream(
        file.filename,
        io.BytesIO(data),
        metadata={"contentType": content_type}
    )
    return url_for("serve_image", file_id=str(file_id))

def delete_gridfs_image(image_path):
    """Delete a GridFS-backed image given the stored /media/<id> path. No-op for external URLs."""
    if not image_path or not image_path.startswith("/media/"):
        return
    file_id = safe_objectid(image_path.rsplit("/", 1)[-1])
    if file_id:
        try:
            fs_bucket.delete(file_id)
        except NoFile:
            pass

# ==========================
# IN-PROCESS IMAGE CACHE
# ==========================
# GridFS reads on the free-tier Atlas cluster are slow (multi-second for a single
# image). Every product photo would otherwise be re-fetched from Mongo on every
# single page view by every shopper, which overwhelms the small gunicorn worker
# pool under real traffic. Caching bytes in memory means each image is only ever
# fetched from GridFS once per worker process, not once per request.
_IMAGE_CACHE_MAX_ITEMS = 150
_image_cache = OrderedDict()
_image_cache_lock = threading.Lock()

def _get_cached_image(file_id_str):
    with _image_cache_lock:
        entry = _image_cache.get(file_id_str)
        if entry is not None:
            _image_cache.move_to_end(file_id_str)
        return entry

def _store_cached_image(file_id_str, data, content_type):
    with _image_cache_lock:
        _image_cache[file_id_str] = (data, content_type)
        _image_cache.move_to_end(file_id_str)
        while len(_image_cache) > _IMAGE_CACHE_MAX_ITEMS:
            _image_cache.popitem(last=False)

try:
    orders_collection.create_index("paymentReference", unique=True)
except Exception:
    pass

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

def unread_messages_count():
    return messages_collection.count_documents({"read": False})

def generate_order_reference():
    """Generate a unique-enough, human-readable order reference."""
    return "KIKKY-" + secrets.token_hex(4).upper()

def validate_product_data(name, price, stock, length, category, sale_price=None):
    """Validate common product fields. Return (is_valid, error_message)."""
    if not name or not name.strip():
        return False, "Product name is required."
    try:
        price_val = float(price)
        if price_val < 0:
            return False, "Price cannot be negative."
    except (ValueError, TypeError):
        return False, "Price must be a valid number."

    if sale_price is not None and str(sale_price).strip() != "":
        try:
            sale_price_val = float(sale_price)
            if sale_price_val < 0:
                return False, "Sale price cannot be negative."
            if sale_price_val >= price_val:
                return False, "Sale price must be less than the normal price."
        except (ValueError, TypeError):
            return False, "Sale price must be a valid number."

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

def get_effective_price(product):
    """Return the sale price if it's set and valid (positive, less than the normal price), else the normal price."""
    price = product.get("price", 0) or 0
    sale_price = product.get("sale_price")
    if sale_price and sale_price > 0 and sale_price < price:
        return sale_price
    return price

def mark_order_paid(reference, order):
    """Decrement stock for an order the first time it's confirmed Paid, and record when.
    Safe to call more than once - only acts if stock hasn't already been deducted."""
    if order.get("stockDeducted", True):
        return
    for item in order.get("items", []):
        obj_id = safe_objectid(item.get("productId"))
        quantity = item.get("quantity", 1)
        if obj_id:
            products_collection.update_one(
                {"_id": obj_id, "stock": {"$gte": quantity}},
                {"$inc": {"stock": -quantity}}
            )
    orders_collection.update_one(
        {"paymentReference": reference},
        {"$set": {
            "status": "Paid",
            "stockDeducted": True,
            "paidAt": datetime.datetime.utcnow()
        }}
    )

# ==========================
# SQUAD PAYMENT HELPERS
# ==========================
def squad_initiate_transaction(reference, amount, email, customer_name, callback_url):
    """Ask Squad to open a checkout session. Returns the checkout_url, or None on failure."""
    try:
        response = requests.post(
            f"{SQUAD_BASE_URL}/transaction/initiate",
            headers={
                "Authorization": f"Bearer {SQUAD_SECRET_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "email": email,
                "amount": int(round(amount * 100)),  # kobo
                "currency": "NGN",
                "initiate_type": "inline",
                "transaction_ref": reference,
                "callback_url": callback_url,
                "customer_name": customer_name,
                "payment_channels": ["card", "bank", "ussd", "transfer"],
                "pass_charge": True  # customer pays Squad's fee on top; merchant is settled the full order amount
            },
            timeout=15
        )
        result = response.json()
    except Exception:
        return None, "Could not reach the payment gateway. Please try again."

    if response.status_code == 200 and result.get("data", {}).get("checkout_url"):
        return result["data"]["checkout_url"], None
    return None, result.get("message", "Payment gateway declined the request.")

def squad_verify_transaction(reference):
    """Check the real status of a transaction with Squad. Returns 'Success', 'Failed', or None on error."""
    try:
        response = requests.get(
            f"{SQUAD_BASE_URL}/transaction/verify/{reference}",
            headers={"Authorization": f"Bearer {SQUAD_SECRET_KEY}"},
            timeout=15
        )
        result = response.json()
    except Exception:
        return None

    if response.status_code == 200 and result.get("success"):
        return result.get("data", {}).get("transaction_status")
    return "Failed"

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

def find_shop_products(category, search_query):
    """Search takes priority over category browsing when both are present."""
    if search_query:
        pattern = re.escape(search_query)
        query = {"$or": [
            {"name": {"$regex": pattern, "$options": "i"}},
            {"category": {"$regex": pattern, "$options": "i"}},
            {"description": {"$regex": pattern, "$options": "i"}},
        ]}
    elif category:
        query = {"category": {"$regex": f"^{re.escape(category)}$", "$options": "i"}}
    else:
        query = {}
    return convert_cursor(products_collection.find(query))

@app.route("/collection")
def collection():
    category = request.args.get("category", "").strip()
    search_query = request.args.get("search", "").strip()
    products = find_shop_products(category, search_query)
    return render_template("shop.html", products=products, active_category=category, search_query=search_query)

@app.route("/shop")
def shop():
    category = request.args.get("category", "").strip()
    search_query = request.args.get("search", "").strip()
    products = find_shop_products(category, search_query)
    return render_template("shop.html", products=products, active_category=category, search_query=search_query)

@app.route("/cart")
def cart():
    return render_template("cart.html")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        name = (data.get("name") or "").strip()
        email = (data.get("email") or "").strip()
        subject = (data.get("subject") or "").strip()
        message = (data.get("message") or "").strip()

        if not name or not email or not message:
            return jsonify({"message": "Name, email and message are required."}), 400

        messages_collection.insert_one({
            "name": name,
            "email": email,
            "subject": subject,
            "message": message,
            "createdAt": datetime.datetime.utcnow(),
            "read": False
        })
        return jsonify({"message": "Message sent successfully."})

    return render_template("contact.html")

@app.route("/media/<file_id>")
def serve_image(file_id):
    obj_id = safe_objectid(file_id)
    if not obj_id:
        abort(404, description="Invalid image ID.")

    cached = _get_cached_image(file_id)
    if cached is not None:
        data, content_type = cached
    else:
        try:
            grid_out = fs_bucket.open_download_stream(obj_id)
        except NoFile:
            abort(404, description="Image not found.")
        content_type = (grid_out.metadata or {}).get("contentType", "application/octet-stream")
        data = grid_out.read()
        _store_cached_image(file_id, data, content_type)

    response = Response(data, mimetype=content_type)
    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response

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
# CHECKOUT ROUTES
# ==========================
@app.route("/checkout")
def checkout():
    return render_template("checkout.html")

@app.route("/order/<reference>")
def order_status(reference):
    order = orders_collection.find_one({"paymentReference": reference})
    if not order:
        abort(404, description="Order not found.")
    order = convert_doc(order)
    return render_template("order_status.html", order=order)

@app.route("/place-order", methods=["POST"])
def place_order():
    """Create the order, then hand off to Squad for payment. Stock is only deducted once Squad confirms payment."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"message": "Invalid request"}), 400

    name = (data.get("name") or "").strip()
    phone = (data.get("phone") or "").strip()
    whatsapp = (data.get("whatsapp") or "").strip()
    email = (data.get("email") or "").strip()
    address = (data.get("address") or "").strip()
    cart_items = data.get("items", [])

    if not name or not phone or not address or not email:
        return jsonify({"message": "Name, email, phone and delivery address are required."}), 400
    if not cart_items:
        return jsonify({"message": "Your cart is empty."}), 400

    order_items = []
    amount = 0
    stock_errors = []
    for item in cart_items:
        product_id = item.get("id") or item.get("productId")
        quantity = item.get("quantity", 1)
        try:
            quantity = int(quantity)
        except (ValueError, TypeError):
            quantity = 1
        if quantity < 1:
            quantity = 1

        obj_id = safe_objectid(product_id)
        if not obj_id:
            stock_errors.append(f"Invalid product: {product_id}")
            continue
        product = products_collection.find_one({"_id": obj_id})
        if not product:
            stock_errors.append(f"Product not found: {product_id}")
            continue
        if product.get("stock", 0) < quantity:
            stock_errors.append(
                f"Insufficient stock for {product.get('name', product_id)}. "
                f"Available: {product.get('stock', 0)}, requested: {quantity}"
            )
            continue

        price = get_effective_price(product)
        order_items.append({
            "productId": str(obj_id),
            "name": product.get("name", "Product"),
            "price": price,
            "quantity": quantity
        })
        amount += price * quantity

    if stock_errors:
        return jsonify({"message": "Stock validation failed", "errors": stock_errors}), 400
    if not order_items:
        return jsonify({"message": "No valid items in cart."}), 400

    order_doc = {
        "customerName": name,
        "customerPhone": phone,
        "customerWhatsapp": whatsapp,
        "customerEmail": email,
        "customerAddress": address,
        "items": order_items,
        "amount": amount,
        "status": "Pending Payment",
        "stockDeducted": False,
        "createdAt": datetime.datetime.utcnow(),
        "paidAt": None
    }

    reference = None
    for _ in range(5):
        candidate = generate_order_reference()
        order_doc["paymentReference"] = candidate
        try:
            orders_collection.insert_one(order_doc)
            reference = candidate
            break
        except Exception:
            continue

    if not reference:
        return jsonify({"message": "Could not generate a unique order reference, please try again."}), 500

    callback_url = url_for("squad_callback", reference=reference, _external=True)
    checkout_url, error = squad_initiate_transaction(reference, amount, email, name, callback_url)

    if not checkout_url:
        return jsonify({
            "message": "Order saved, but the payment gateway couldn't be reached.",
            "reference": reference,
            "amount": amount,
            "payment_error": error
        }), 502

    return jsonify({
        "message": "Order placed",
        "reference": reference,
        "amount": amount,
        "checkout_url": checkout_url
    })

@app.route("/squad/callback")
def squad_callback():
    """Squad redirects the customer's browser here after they finish (or abandon) checkout.
    Never trust the redirect alone - always verify the real status with Squad server-side."""
    reference = request.args.get("reference", "").strip()
    if not reference:
        abort(404, description="Missing order reference.")

    order = orders_collection.find_one({"paymentReference": reference})
    if not order:
        abort(404, description="Order not found.")

    status = squad_verify_transaction(reference)
    if status == "Success":
        mark_order_paid(reference, order)

    return redirect(url_for("order_status", reference=reference))

@app.route("/squad/webhook", methods=["POST"])
def squad_webhook():
    """Server-to-server notification from Squad - the reliable path for marking orders Paid.
    The browser redirect in /squad/callback is a nice-to-have for fast confirmation, but if a
    customer pays and then closes the tab, loses signal, or never makes it back to our site,
    this webhook is what actually credits the sale and reduces stock. Must be configured once
    in the Squad dashboard under Profile > API & Webhook."""
    raw_body = request.get_data()
    signature = request.headers.get("x-squad-encrypted-body", "")

    expected = hmac.new(SQUAD_SECRET_KEY.encode(), raw_body, hashlib.sha512).hexdigest().upper()
    if not signature or not hmac.compare_digest(expected, signature.upper()):
        return jsonify({"message": "Invalid signature"}), 401

    payload = request.get_json(silent=True) or {}
    body = payload.get("Body", {})

    if payload.get("Event") != "charge_successful" or body.get("transaction_status") != "Success":
        return jsonify({"message": "Ignored"}), 200

    reference = body.get("transaction_ref") or payload.get("TransactionRef")
    order = orders_collection.find_one({"paymentReference": reference}) if reference else None
    if order:
        mark_order_paid(reference, order)

    return jsonify({"message": "OK"}), 200

@app.route("/track-order", methods=["GET", "POST"])
def track_order():
    orders = None
    searched = False
    if request.method == "POST":
        searched = True
        query_value = (request.form.get("query") or "").strip()
        if query_value:
            orders = convert_cursor(orders_collection.find({
                "$or": [
                    {"customerPhone": query_value},
                    {"customerWhatsapp": query_value},
                    {"customerEmail": query_value},
                    {"paymentReference": query_value}
                ]
            }).sort("createdAt", -1))
    return render_template("track-order.html", orders=orders, searched=searched)

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
            flash("Invalid email or password.", "error")
            return redirect(url_for("admin_login_page"))

        if not bcrypt.checkpw(password.encode(), admin["password"]):
            flash("Invalid email or password.", "error")
            return redirect(url_for("admin_login_page"))

        token = jwt.encode(
            {
                "id": str(admin["_id"]),
                "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
            },
            JWT_SECRET,
            algorithm="HS256"
        )

        response = redirect(url_for("admin_products"))
        # Secure cookie flags
        response.set_cookie(
            "admin_token",
            token,
            httponly=True,
            secure=os.getenv("FLASK_ENV") == "production",  # only secure in production
            samesite="Lax"
        )
        flash("Login successful.", "success")
        return response

    return render_template("admin_login.html")

@app.route("/admin/logout")
@token_required
def admin_logout(current_admin):
    response = redirect(url_for("admin_login_page"))
    response.delete_cookie("admin_token")
    flash("You have been logged out.")
    return response

@app.route("/admin/dashboard")
@token_required
def admin_dashboard(current_admin):
    return redirect(url_for("admin_products"))

@app.route("/admin/add-product-page")
@token_required
def admin_add_product_page(current_admin):
    return render_template("admin_add_product.html", unread_messages=unread_messages_count())

@app.route("/admin/products")
@token_required
def admin_products(current_admin):
    products = convert_cursor(products_collection.find())
    return render_template("admin_products.html", products=products, unread_messages=unread_messages_count())

@app.route("/admin/stock")
@token_required
def admin_stock(current_admin):
    products = convert_cursor(products_collection.find())
    total_stock = sum(p.get("stock", 0) for p in products)
    sold_out_count = sum(1 for p in products if p.get("stock", 0) <= 0)

    sold_by_product = {}
    for order in orders_collection.find({"status": {"$in": ["Paid", "Shipped", "Delivered"]}}):
        for item in order.get("items", []):
            pid = item.get("productId")
            sold_by_product[pid] = sold_by_product.get(pid, 0) + item.get("quantity", 0)

    for p in products:
        p["sold"] = sold_by_product.get(p["_id"], 0)
    total_sold = sum(sold_by_product.values())

    return render_template(
        "admin_stock.html",
        products=products,
        total_stock=total_stock,
        sold_out_count=sold_out_count,
        total_sold=total_sold,
        unread_messages=unread_messages_count()
    )

@app.route("/admin/orders")
@token_required
def admin_orders(current_admin):
    orders = convert_cursor(orders_collection.find().sort("createdAt", -1))
    return render_template("admin_orders.html", orders=orders, unread_messages=unread_messages_count())

@app.route("/admin/messages")
@token_required
def admin_messages(current_admin):
    messages = convert_cursor(messages_collection.find().sort("createdAt", -1))
    messages_collection.update_many({"read": False}, {"$set": {"read": True}})
    return render_template("admin_messages.html", messages=messages, unread_messages=0)

@app.route("/admin/register", methods=["GET", "POST"])
@token_required
def admin_register(current_admin):
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("admin_register"))

        if password != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for("admin_register"))

        if admins_collection.find_one({"email": email}):
            flash("An admin with that email already exists.", "error")
            return redirect(url_for("admin_register"))

        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        admins_collection.insert_one({
            "email": email,
            "password": hashed,
            "created_by": current_admin["email"],
            "role": "admin"
        })

        flash("New admin created successfully!", "success")
        return redirect(url_for("admin_products"))

    return render_template("admin_register.html")

@app.route("/admin/edit-product/<product_id>", methods=["GET", "POST"])
@token_required
def edit_product(current_admin, product_id):
    obj_id = safe_objectid(product_id)
    if not obj_id:
        flash("Invalid product ID.")
        return redirect(url_for("admin_products"))

    product = products_collection.find_one({"_id": obj_id})
    if not product:
        flash("Product not found.")
        return redirect(url_for("admin_products"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price = request.form.get("price")
        sale_price = request.form.get("sale_price")
        category = request.form.get("category", "").strip()
        length = request.form.get("length")
        stock = request.form.get("stock")
        description = request.form.get("description", "").strip()

        is_valid, error_msg = validate_product_data(name, price, stock, length, category, sale_price)
        if not is_valid:
            flash(error_msg)
            return redirect(url_for("edit_product", product_id=product_id))

        # Prepare update data
        update_data = {
            "name": name,
            "price": float(price),
            "sale_price": float(sale_price) if sale_price and sale_price.strip() else None,
            "category": category,
            "length": int(length),
            "stock": int(stock),
            "description": description
        }

        # Check if new image was uploaded
        if 'image' in request.files and request.files['image'].filename != '':
            file = request.files['image']
            
            if not allowed_file(file.filename):
                flash("Invalid file type. Allowed: png, jpg, jpeg, gif, webp.")
                return redirect(url_for("edit_product", product_id=product_id))
            
            # Upload new image to GridFS, then clean up the old one
            try:
                image_url = upload_to_gridfs(file)
                update_data["image"] = image_url
                delete_gridfs_image(product.get("image", ""))
            except Exception as e:
                flash(f"Image upload failed: {str(e)}")
                return redirect(url_for("edit_product", product_id=product_id))

        # Update product in database
        products_collection.update_one(
            {"_id": obj_id},
            {"$set": update_data}
        )
        
        flash("Product updated successfully.")
        return redirect(url_for("admin_products"))

    product = convert_doc(product)
    return render_template("edit_product.html", product=product)

@app.route("/admin/add-product", methods=["POST"])
@token_required
def add_product(current_admin):
    # Validate required fields
    name = request.form.get("name", "").strip()
    price = request.form.get("price")
    sale_price = request.form.get("sale_price")
    description = request.form.get("description", "").strip()
    stock = request.form.get("stock")
    category = request.form.get("category", "").strip()
    length = request.form.get("length")

    is_valid, error_msg = validate_product_data(name, price, stock, length, category, sale_price)
    if not is_valid:
        flash(error_msg)
        return redirect(url_for("admin_add_product_page"))

    # Handle file upload
    if 'image' not in request.files:
        flash("No image file provided.")
        return redirect(url_for("admin_add_product_page"))

    file = request.files['image']
    if file.filename == '':
        flash("No selected file.")
        return redirect(url_for("admin_add_product_page"))

    if not allowed_file(file.filename):
        flash("Invalid file type. Allowed: png, jpg, jpeg, gif, webp.")
        return redirect(url_for("admin_add_product_page"))

    # Upload to GridFS
    try:
        image_url = upload_to_gridfs(file)
    except Exception as e:
        flash(f"Image upload failed: {str(e)}")
        return redirect(url_for("admin_add_product_page"))

    # Insert product
    product_data = {
        "name": name,
        "price": float(price),
        "sale_price": float(sale_price) if sale_price and sale_price.strip() else None,
        "image": image_url,
        "description": description,
        "stock": int(stock),
        "category": category,
        "length": int(length)
    }
    products_collection.insert_one(product_data)
    flash("Product added successfully.")
    return redirect(url_for("admin_products"))

@app.route("/admin/delete-product/<product_id>")
@token_required
def delete_product(current_admin, product_id):
    obj_id = safe_objectid(product_id)
    if not obj_id:
        flash("Invalid product ID.")
        return redirect(url_for("admin_products"))

    product = products_collection.find_one({"_id": obj_id})
    result = products_collection.delete_one({"_id": obj_id})
    if result.deleted_count == 0:
        flash("Product not found.")
    else:
        if product:
            delete_gridfs_image(product.get("image", ""))
        flash("Product deleted successfully.")
    return redirect(url_for("admin_products"))

@app.route("/admin/delete-all-products", methods=["POST"])
@token_required
def delete_all_products(current_admin):
    products = list(products_collection.find({}, {"image": 1}))
    for product in products:
        delete_gridfs_image(product.get("image", ""))
    result = products_collection.delete_many({})
    flash(f"Deleted {result.deleted_count} product(s) and their images.")
    return redirect(url_for("admin_products"))

@app.route("/admin/update-order/<reference>", methods=["POST"])
@token_required
def update_order(current_admin, reference):
    new_status = request.form.get("status")
    if not new_status:
        flash("Status is required.")
        return redirect(url_for("admin_orders"))

    order = orders_collection.find_one({"paymentReference": reference})
    if not order:
        flash("Order not found.")
        return redirect(url_for("admin_orders"))

    if new_status == "Paid":
        mark_order_paid(reference, order)
    else:
        orders_collection.update_one({"paymentReference": reference}, {"$set": {"status": new_status}})

    flash("Order status updated.")
    return redirect(url_for("admin_orders"))

@app.route("/admin/delete-order/<reference>")
@token_required
def delete_order(current_admin, reference):
    result = orders_collection.delete_one({"paymentReference": reference})
    if result.deleted_count == 0:
        flash("Order not found.")
    else:
        flash("Order deleted successfully.")
    return redirect(url_for("admin_orders"))


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