from dotenv import load_dotenv
load_dotenv()

import os
import requests
import random
import uuid
import io
import base64
import zipfile
import csv
from functools import wraps
import time
from datetime import datetime, timezone, timedelta

from flask import (
    Flask, flash, redirect, render_template, request, session, get_flashed_messages,
    url_for, abort, g, jsonify, send_file, Response, after_this_request
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
from sqlalchemy.dialects.sqlite import JSON
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from urllib.parse import quote_plus
from flask_babel import Babel, gettext as _
from flask_dance.contrib.google import make_google_blueprint, google
from flask_mail import Mail, Message
from PIL import Image, ExifTags
import PyPDF2
from deep_translator import GoogleTranslator
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2 import cbor
from markupsafe import Markup
from sympy import symbols, sympify, integrate, diff, solve, Eq, sin, cos, tan, exp, log, Matrix, asin, acos, atan, acot, asec, acsc, sinh, cosh, tanh, coth, sech, csch, asinh, acosh, atanh, acoth, asech, acsch, cot, sec, csc, pi, E
from openai import OpenAI
import google.generativeai as genai

# --- Configuration ---
ON_RENDER = os.environ.get('RENDER', None) == 'true'

if not ON_RENDER:
    load_dotenv('.env')

BIGDATACLOUD_API_KEY = os.environ.get("BIGDATACLOUD_API_KEY")
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))

# --- Flask App Setup ---
app = Flask(__name__)
app.config["SESSION_TYPE"] = "null"
app.config["SESSION_PERMANENT"] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['DEBUG'] = os.getenv('DEBUG', 'False') == 'True'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

# --- Database Setup ---
db = SQLAlchemy()
# Use DATABASE_URL from environment (Render) if available, else default to SQLite
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    # Render may provide postgres://, but SQLAlchemy expects postgresql://
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    db_name = os.path.join(os.path.dirname(__file__), 'users.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_name
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# --- Babel ---
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'
babel = Babel(app)

# --- Google OAuth ---
google_bp = make_google_blueprint(
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ],
    redirect_to="index"
)
app.register_blueprint(google_bp, url_prefix="/login")

# --- Mail ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get("MAIL_USERNAME") or "no-reply@neobox.com"
mail = Mail(app)

# --- FIDO2 Passkey ---
rp = PublicKeyCredentialRpEntity(id="localhost", name="CS50 FP Demo")
fido2_server = Fido2Server(rp)

# --- Models ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True)
    dob = db.Column(db.Date)
    gender = db.Column(db.String(10))
    hash = db.Column(db.String(120), nullable=False)
    avatar_url = db.Column(db.String(255))
    bio = db.Column(db.Text)
    location = db.Column(db.String(100))
    website = db.Column(db.String(200))
    company = db.Column(db.String(100))
    position = db.Column(db.String(100))
    google_id = db.Column(db.String(128), unique=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    language = db.Column(db.String(10), default='en')
    theme = db.Column(db.String(10), default='auto')
    reset_token = db.Column(db.String(100), nullable=True)
    verified = db.Column(db.Boolean, default=False)
    verify_token = db.Column(db.String(100), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    notifications_enabled = db.Column(db.Boolean, default=True)
    privacy_level = db.Column(db.String(20), default='public')
    last_active = db.Column(db.DateTime)
    otp = db.Column(db.String(10), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    passkeys = db.Column(JSON, default=list)
    delete_requested_at = db.Column(db.DateTime, nullable=True)

class Visitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, nullable=False)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    message = db.Column(db.String(255))
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    email = db.Column(db.String(120))
    rating = db.Column(db.Integer)
    message = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))
    screenshot_url = db.Column(db.String(255))
    status = db.Column(db.String(20), default='pending')
    admin_response = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    content = db.Column(db.Text)
    due_date = db.Column(db.Date)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(255))
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# --- Utility Functions and Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename, types):
    ext = filename.rsplit('.', 1)[1].lower()
    return any(ext in ALLOWED_EXTENSIONS[t] for t in types if t in ALLOWED_EXTENSIONS)

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(user, otp):
    msg = Message(
        subject="Your OTP Verification Code",
        recipients=[user.email],
        body=f"Your OTP code is: {otp}\nThis code will expire in 10 minutes."
    )
    mail.send(msg)

def log_activity(user_id, action, details=""):
    log = ActivityLog(user_id=user_id, action=action, details=details)
    db.session.add(log)
    db.session.commit()

# --- Context Processors and Hooks ---
@app.context_processor
def inject_globals():
    return {
        'now': datetime.now(timezone.utc),
        'available_languages': AVAILABLE_LANGUAGES,
        'timedelta': timedelta
    }

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.before_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user = User.query.get(user_id) if user_id else None

# --- Routes ---
@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/")
def index():
    if session.get("user_id"):
        frequent_tools = TOOLS[:3]
        # Get notifications for user
        notifications = Notification.query.filter_by(user_id=session["user_id"]).order_by(Notification.created_at.desc()).all()
        import random
        daily_quote = random.choice(DAILY_QUOTES)
        daily_question = random.choice(DAILY_QUESTIONS)
        return render_template(
            "index.html",
            frequent_tools=frequent_tools,
            notifications=notifications,
            daily_quote=daily_quote,
            daily_question=daily_question,
        )
    else:
        ip = request.remote_addr
        if not Visitor.query.filter_by(ip=ip).first():
            db.session.add(Visitor(ip=ip))
            db.session.commit()
        count = Visitor.query.count()
        return render_template("landing.html", visitor_count=count, _=_)

# --- Registration Route ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip()
        email = request.form.get("email").strip().lower()
        phone = request.form.get("phone").strip()
        dob = request.form.get("dob")
        gender = request.form.get("gender")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        # Validation
        if not username or not email or not password or not confirmation:
            flash("All required fields must be filled.", "danger")
            return render_template("register.html")
        if password != confirmation:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
        if User.query.filter((User.username == username) | (User.email == email) | (User.phone == phone)).first():
            flash("Username, email, or phone already exists.", "danger")
            return render_template("register.html")
        # Convert dob string to date object
        dob_obj = None
        if dob:
            try:
                dob_obj = datetime.strptime(dob, "%Y-%m-%d").date()
            except Exception:
                flash("Invalid date of birth format.", "danger")
                return render_template("register.html")
        # Create user (unverified)
        hash_pw = generate_password_hash(password)
        otp = generate_otp()
        otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
        user = User(
            username=username,
            email=email,
            phone=phone,
            dob=dob_obj,  # Use the date object here
            gender=gender,
            hash=hash_pw,
            verified=False,
            otp=otp,
            otp_expiry=otp_expiry
        )
        db.session.add(user)
        db.session.commit()
        # --- New Verification Logic ---
        verify_token = uuid.uuid4().hex
        user.verify_token = verify_token
        db.session.commit()
        verify_url = url_for('verify', token=verify_token, _external=True)
        msg = Message(
            subject="Verify your account",
            recipients=[user.email],
            body=f"Click this link to verify your account: {verify_url}\nOr enter the OTP: {otp}"
        )
        mail.send(msg)
        session["pending_user_id"] = user.id
        flash("Registration successful! Please check your email for the OTP to verify your account.", "info")
        return redirect(url_for("verify_otp"))
    return render_template("register.html")

# --- OTP Verification Route ---
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    user_id = session.get("pending_user_id")
    if not user_id:
        flash("No verification in progress.", "warning")
        return redirect("/login")

    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect("/register")

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()

        # Validate input
        if not otp:
            flash("Please enter the OTP.", "danger")
            return render_template("verify_otp.html", email=user.email)

        # Normalize OTP expiry (make timezone-aware)
        otp_expiry = user.otp_expiry
        if otp_expiry and otp_expiry.tzinfo is None:
            otp_expiry = otp_expiry.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        # Check if OTP is invalid or expired
        if (
            user.otp != otp
            or not otp_expiry
            or now > otp_expiry
        ):
            flash("Invalid or expired OTP.", "danger")
            return render_template("verify_otp.html", email=user.email)

        # Mark user as verified
        user.verified = True
        user.otp = None
        user.otp_expiry = None
        db.session.commit()

        # Clean up session
        session.pop("pending_user_id", None)
        session["user_id"] = user.id

        flash("Your account has been verified! Welcome!", "success")
        return redirect("/")

    return render_template("verify_otp.html", email=user.email)

# --- Resend OTP Route ---
@app.route("/resend-otp")
def resend_otp():
    user_id = session.get("pending_user_id")
    if not user_id:
        flash("No verification in progress.", "warning")
        return redirect("/login")
    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect("/register")
    otp = generate_otp()
    user.otp = otp
    user.otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    db.session.commit()
    send_otp_email(user, otp)
    flash("A new OTP has been sent to your email.", "info")
    return redirect(url_for("verify_otp"))

# --- Login Route (block unverified) ---
@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        identifier = request.form.get("identifier").strip()
        password = request.form.get("password")
        user = User.query.filter((User.username == identifier) | (User.email == identifier) | (User.phone == identifier)).first()
        if not user or not check_password_hash(user.hash, password):
            flash("Invalid credentials.", "danger")
            return render_template("login.html")
        if not user.verified:
            session["pending_user_id"] = user.id
            flash("Account not verified. Please check your email for the OTP.", "warning")
            return redirect(url_for("verify_otp"))
        session["user_id"] = user.id
        flash("Logged in successfully!", "success")
        return redirect("/")
    return render_template("login.html")

# --- Forgot Password (send OTP) ---
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email").strip().lower()
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with that email.", "danger")
            return render_template("forgot.html")
        otp = generate_otp()
        user.otp = otp
        user.otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
        db.session.commit()
        send_otp_email(user, otp)
        session["reset_user_id"] = user.id
        flash("An OTP has been sent to your email for password reset.", "info")
        return redirect(url_for("reset_otp"))
    return render_template("forgot.html")

# --- Forgot Password (send token link) ---
@app.route("/forgot-token", methods=["GET", "POST"])
def forgot_token():
    if request.method == "POST":
        email = request.form.get("email").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = os.urandom(24).hex()
            user.reset_token = token
            db.session.commit()
            reset_url = url_for('reset', token=token, _external=True)
            msg = Message("Password Reset", recipients=[email], body=f"Reset your password: {reset_url}")
            mail.send(msg)
            flash("Check your email for a reset link.", "info")
        else:
            flash("No account with that email.", "danger")
        return redirect("/forgot-token")
    return render_template("forgot.html")

# --- OTP Verification for Password Reset ---
@app.route("/reset-otp", methods=["GET", "POST"])
def reset_otp():
    user_id = session.get("reset_user_id")
    if not user_id:
        flash("No password reset in progress.", "warning")
        return redirect("/forgot")
    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect("/forgot")
    if request.method == "POST":
        otp = request.form.get("otp").strip()
        if not otp:
            flash("Please enter the OTP.", "danger")
            return render_template("verify_otp.html")
        if user.otp != otp or not user.otp_expiry or datetime.now(timezone.utc) > user.otp_expiry:
            flash("Invalid or expired OTP.", "danger")
            return render_template("verify_otp.html")
        # OTP valid, allow password reset
        session["reset_token"] = os.urandom(24).hex()
        user.reset_token = session["reset_token"]
        user.otp = None
        user.otp_expiry = None
        db.session.commit()
        return redirect(url_for("reset", token=user.reset_token))
    return render_template("verify_otp.html", email=user.email, reset=True)

# --- Resend OTP for Password Reset ---
@app.route("/resend-reset-otp")
def resend_reset_otp():
    user_id = session.get("reset_user_id")
    if not user_id:
        flash("No password reset in progress.", "warning")
        return redirect("/forgot")
    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect("/forgot")
    otp = generate_otp()
    user.otp = otp
    user.otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    db.session.commit()
    send_otp_email(user, otp)
    flash("A new OTP has been sent to your email.", "info")
    return redirect(url_for("reset_otp"))

# --- Reset Password Route (token) ---
@app.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        flash("Invalid or expired reset link.", "danger")
        return redirect("/forgot")
    if request.method == "POST":
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not password or not confirmation:
            flash("Please fill out all fields.", "danger")
            return render_template("reset.html", token=token)
        if password != confirmation:
            flash("Passwords do not match.", "danger")
            return render_template("reset.html", token=token)
        user.hash = generate_password_hash(password)
        user.reset_token = None
        db.session.commit()
        session.pop("reset_user_id", None)
        session.pop("reset_token", None)
        flash("Password reset successful! You can now log in.", "success")
        return redirect("/login")
    return render_template("reset.html", token=token)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect("/login")

@app.route("/change", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirmation", "")

        if not current or not new or not confirm:
            flash("All fields are required.", "danger")
            return redirect("/change")
        if new != confirm:
            flash("Passwords do not match.", "danger")
            return redirect("/change")

        user = db.session.execute(
            text("SELECT hash FROM users WHERE id = :id"), {"id": session["user_id"]}
        ).mappings().fetchone()
        if not user or not check_password_hash(user["hash"], current):
            flash("Incorrect current password.", "danger")
            return redirect("/change")

        new_hash = generate_password_hash(new)
        db.session.execute(
            text("UPDATE users SET hash = :new_hash WHERE id = :id"),
            {"new_hash": new_hash, "id": session["user_id"]}
        )
        db.session.commit()
        flash("Password updated successfully!", "success")
        return redirect("/")

    return render_template("change.html")

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = User.query.get(session["user_id"])
    if request.method == "POST":
        phone = request.form.get("phone")
        dob = request.form.get("dob")
        gender = request.form.get("gender")
        if phone and User.query.filter(User.phone == phone, User.id != user.id).first():
            flash("Phone number already in use.", "danger")
            return redirect("/profile")
        user.phone = phone
        user.dob = dob
        user.gender = gender
        db.session.commit()
        flash("Profile updated!", "success")
        return redirect("/profile")
    return render_template("profile.html", user=user)

@app.route("/delete-account", methods=["POST"])
@login_required
def delete_account():
    user = User.query.get(session["user_id"])
    if user:
        db.session.delete(user)
        db.session.commit()
        session.clear()
        flash("Account deleted successfully.", "success")
    return redirect("/register")

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        language = request.form.get("language")
        theme = request.form.get("theme")
        db.session.execute(
            text("UPDATE users SET language = :language, theme = :theme WHERE id = :id"),
            {"language": language, "theme": theme, "id": session["user_id"]}
        )
        db.session.commit()
        session["lang"] = language
        session["theme"] = theme
        flash("Settings updated!", "success")
        return redirect("/settings")
    user = db.session.execute(
        text("SELECT * FROM users WHERE id = :id"),
        {"id": session["user_id"]}
    ).mappings().fetchone()
    return render_template("settings.html", user=user)

@app.route("/verify/<token>")
def verify(token):
    user = User.query.filter_by(verify_token=token).first()
    if user:
        user.verified = True
        user.verify_token = None
        db.session.commit()
        flash("Email verified! You can now log in.", "success")
    else:
        flash("Invalid or expired verification link.", "danger")
    return redirect("/login")

@app.route("/set_language/<lang>")
def set_language(lang):
    session["lang"] = lang
    if session.get("user_id"):
        db.session.execute(
            text("UPDATE users SET language = :lang WHERE id = :id"),
            {"lang": lang, "id": session["user_id"]}
        )
        db.session.commit()
    return redirect(request.referrer or "/")

AVAILABLE_LANGUAGES = [
    {"code": "en", "name": "English"},
    {"code": "es", "name": "Español"},
    {"code": "ur", "name": "اردو"},
    {"code": "ar", "name": "العربية"},
]

TOOLS = [
    # Math & Calculators
    {"name": "Calculator", "icon": "bi-calculator", "url": "calculator", "category": "math", "login_required": False, "description": "Simple arithmetic calculator."},
    {"name": "Scientific Calculator", "icon": "bi-calculator", "url": "scientific-calculator", "category": "math", "login_required": False, "description": "Advanced calculator for scientific functions."},
    {"name": "Integration Calculator", "icon": "bi-calculator", "url": "integration-calculator", "category": "math", "login_required": False, "description": "Symbolic and definite integration."},
    {"name": "Differentiation Calculator", "icon": "bi-calculator", "url": "differentiation-calculator", "category": "math", "login_required": False, "description": "Symbolic differentiation."},
    {"name": "Equation Solver", "icon": "bi-calculator", "url": "equation-solver", "category": "math", "login_required": False, "description": "Solve algebraic equations."},
    {"name": "Matrix Calculator", "icon": "bi-grid-3x3-gap", "url": "matrix-calculator", "category": "math", "login_required": False, "description": "Matrix operations (add, multiply, inverse, etc)."},
    {"name": "Complex Number Calculator", "icon": "bi-diagram-3", "url": "complex-calculator", "category": "math", "login_required": False, "description": "Complex number arithmetic."},
    {"name": "Polynomial Calculator", "icon": "bi-diagram-2", "url": "polynomial-calculator", "category": "math", "login_required": False, "description": "Roots, evaluation, derivative, integral."},
    {"name": "Statistics Calculator", "icon": "bi-bar-chart", "url": "statistics-calculator", "category": "math", "login_required": False, "description": "Mean, median, mode, stdev, variance."},
    {"name": "Base Converter", "icon": "bi-123", "url": "base-converter", "category": "math", "login_required": False, "description": "Convert numbers between bases."},
    {"name": "Trigonometry Calculator", "icon": "bi-activity", "url": "trigonometry-calculator", "category": "math", "login_required": False, "description": "Sine, cosine, tangent, etc."},
    {"name": "Fraction Calculator", "icon": "bi-slash-square", "url": "fraction-calculator", "category": "math", "login_required": False, "description": "Fraction arithmetic."},

    # Conversion
    {"name": "Unit Converter", "icon": "bi-arrow-left-right", "url": "unit-converter", "category": "conversion", "login_required": False, "description": "Convert between various units of measurement."},
    {"name": "Currency Converter", "icon": "bi-currency-exchange", "url": "currency-converter", "category": "conversion", "login_required": False, "description": "Convert currencies using real-time rates."},
    {"name": "Flashcards", "icon": "bi-card-list", "url": "flashcards", "category": "productivity", "login_required": False, "description": "Create and study flashcards."},

    # Productivity
    {"name": "Pomodoro Timer", "icon": "bi-hourglass-split", "url": "pomodoro", "category": "productivity", "login_required": False, "description": "Boost productivity with Pomodoro sessions."},

    # Time
    {"name": "Timer", "icon": "bi-stopwatch", "url": "timer", "category": "time", "login_required": False, "description": "Set a countdown timer for any task."},
    {"name": "Stopwatch", "icon": "bi-stopwatch-fill", "url": "stopwatch", "category": "time", "login_required": False, "description": "Track elapsed time with a stopwatch."},

    # AI
    {"name": "Text Translator", "icon": "bi-translate", "url": "translator", "category": "ai", "login_required": False, "description": "Translate text between languages."},
    
    # Files
    {"name": "Image Metadata Viewer", "icon": "bi-info-circle", "url": "image-metadata", "category": "files", "login_required": False, "description": "View metadata of uploaded images."},

    # Science
    {"name": "Interactive Periodic Table", "icon": "bi-tablet", "url": "periodic-table", "category": "science", "login_required": False, "description": "Explore elements and their properties."},
    {"name": "Gradient Generator", "icon": "bi-palette2", "url": "gradient-generator", "category": "science", "login_required": False, "description": "Create CSS gradients with multiple colors."},
    {"name": "Palette Generator", "icon": "bi-palette-fill", "url": "palette-generator", "category": "science", "login_required": False, "description": "Generate harmonious color palettes."},
    {"name": "White Noise Generator", "icon": "bi-soundwave", "url": "white-noise", "category": "science", "login_required": False, "description": "Play white, pink, brown noise and more."},
    {"name": "Astrology/Star Map", "icon": "bi-stars", "url": "star-map", "category": "science", "login_required": False, "description": "View the night sky from any location."},

    # Other
    {"name": "Search Engine Prompt", "icon": "bi-search", "url": "search", "category": "other", "login_required": False, "description": "Quickly search using your favorite search engines."},
    {"name": "URL Shortener", "icon": "bi-link-45deg", "url": "url-shortener", "category": "other", "login_required": False, "description": "Shorten long URLs for easy sharing."},
    {"name": "Custom URL Redirects", "icon": "bi-arrow-right-circle", "url": "url-redirects", "category": "other", "login_required": False, "description": "Create custom redirects for your URLs."},
]

WIP_TOOLS = [
    {"name": "File Converter", "icon": "bi-file-earmark-arrow-down", "url": "file-converter", "category": "files", "login_required": False, "description": "Convert files between different formats."},
    {"name": "World Clocks", "icon": "bi-clock", "url": "world-clock", "category": "time", "login_required": False, "description": "View current times in cities worldwide."},
    {"name": "AI Prompt", "icon": "bi-chat-right-dots", "url": "ai-prompt", "category": "ai", "login_required": False, "description": "Get instant responses from a demo AI."},
    {"name": "Text Summarizer", "icon": "bi-body-text", "url": "ai-summarizer", "category": "ai", "login_required": False, "description": "Summarize long text using AI."},
    {"name": "Text Paraphraser", "icon": "bi-list-columns-reverse", "url": "ai-paraphraser", "category": "ai", "login_required": False, "description": "Paraphrase text using AI."},
    {"name": "Code Explainer", "icon": "bi-code-slash", "url": "ai-code-explainer", "category": "ai", "login_required": False, "description": "Explain code using AI."},
    {"name": "Gemini Prompt", "icon": "bi-google", "url": "ai-gemini-prompt", "category": "ai", "login_required": False, "description": "Ask Gemini (Google AI) anything."},
    {"name": "Reverse Image Search", "icon": "bi-image", "url": "reverse-image-search", "category": "other", "login_required": False, "description": "Find similar images on the web."},
    {"name": "To-do List", "icon": "bi-list-check", "url": "todo", "category": "productivity", "login_required": True, "description": "Manage your personal tasks and to-dos."},
    {"name": "Notes", "icon": "bi-journal-text", "url": "notes", "category": "productivity", "login_required": True, "description": "Write and save personal notes."},
]

UPCOMING_TOOLS = [
    
      {"name": "File Renamer", "icon": "bi-file-earmark-font", "soon": "Renaming soon"},
      {"name": "Text Encryptor/Decryptor", "icon": "bi-shield-lock", "soon": "Encrypting soon"},
      {"name": "Image Enlarger", "icon": "bi-arrows-angle-expand", "soon": "Enlarging soon"},
      {"name": "Daily Routines/Reminders", "icon": "bi-calendar-check", "soon": "Reminding soon"},
      {"name": "Maps", "icon": "bi-geo-alt", "soon": "Mapping soon"},
      {"name": "Custom Calendar", "icon": "bi-calendar-range", "soon": "Planning soon"},
      {"name": "Weather", "icon": "bi-cloud-sun", "soon": "Forecasting soon"},
      {"name": "Password Manager", "icon": "bi-key", "soon": "Securing soon"},
      {"name": "QR Code Tools", "icon": "bi-qr-code-scan", "soon": "Scanning soon"},
      {"name": "Daily Quotes", "icon": "bi-chat-quote", "soon": "Quoting soon"},
      {"name": "Daily Questions", "icon": "bi-question-circle", "soon": "Questioning soon"},
      {"name": "PDF Tools", "icon": "bi-file-earmark-pdf", "soon": "PDFing soon"},
      {"name": "Voice-to-Text", "icon": "bi-mic", "soon": "Listening soon"},
      {"name": "Text-to-Speech", "icon": "bi-volume-up", "soon": "Speaking soon"},
      {"name": "Mind-maps/Flowcharts", "icon": "bi-diagram-3", "soon": "Mapping soon"},
      {"name": "Code Formatter", "icon": "bi-code-slash", "soon": "Formatting soon"},
      {"name": "Expense Tracker", "icon": "bi-cash-stack", "soon": "Tracking soon"},
      {"name": "Budget Tracker", "icon": "bi-wallet2", "soon": "Budgeting soon"},
      {"name": "Habit Tracker", "icon": "bi-check2-circle", "soon": "Habiting soon"},
      {"name": "Grocery List Manager", "icon": "bi-basket", "soon": "Shopping soon"},
      {"name": "Health Tracker", "icon": "bi-heart-pulse", "soon": "Monitoring soon"},
      {"name": "Random Generator", "icon": "bi-shuffle", "soon": "Randomizing soon"},
      {"name": "Collaborative Notes", "icon": "bi-people", "soon": "Collaborating soon"},
      {"name": "Basic Drawing", "icon": "bi-brush", "soon": "Drawing soon"},
      {"name": "Stock/Market Tracker", "icon": "bi-graph-up", "soon": "Analyzing soon"},
      {"name": "Bookmark Manager", "icon": "bi-bookmark-star", "soon": "Bookmarking soon"},
      {"name": "World Clock & Meeting Planner", "icon": "bi-globe", "soon": "Planning soon"},
      {"name": "Music/Audio Player", "icon": "bi-music-note-beamed", "soon": "Playing soon"},
      {"name": "Video/Image Compressor", "icon": "bi-file-earmark-zip", "soon": "Compressing soon"},
      {"name": "Image Editor", "icon": "bi-image-alt", "soon": "Editing soon"},
      {"name": "Markdown Editor", "icon": "bi-filetype-md", "soon": "Markdowning soon"},
      {"name": "JSON Formatter/Validator", "icon": "bi-code-square", "soon": "Validating soon"},
      {"name": "Text Formatter", "icon": "bi-textarea", "soon": "Formatting soon"},
      {"name": "Text Reverser", "icon": "bi-arrow-repeat", "soon": "Reversing soon"},
      {"name": "Text Analyzer", "icon": "bi-bar-chart-line", "soon": "Analyzing soon"},
      {"name": "Text Expander", "icon": "bi-textarea-t", "soon": "Expanding soon"},
      {"name": "Text Summarizer", "icon": "bi-textarea-t", "soon": "Summarizing soon"},
      {"name": "Text Case Converter", "icon": "bi-textarea-resize", "soon": "Converting soon"},
      {"name": "Image to Text (OCR)", "icon": "bi-filetype-txt", "soon": "Extracting soon"},
      {"name": "Focus Session", "icon": "bi-bullseye", "soon": "Focusing soon"},
      {"name": "Study Laps", "icon": "bi-journal-check", "soon": "Tracking soon"},
      {"name": "Mood Tracker", "icon": "bi-emoji-smile", "soon": "Mood tracking soon"},
      {"name": "Screen Color Tool", "icon": "bi-lightbulb", "soon": "Lighting soon"},
      {"name": "Collaborative Documents", "icon": "bi-file-earmark-text", "soon": "Collaborating soon"},
      {"name": "Event Planner", "icon": "bi-calendar-event", "soon": "Planning soon"},
      {"name": "Game Zone", "icon": "bi-controller", "soon": "Gaming soon"},
      {"name": "Regex Tester", "icon": "bi-slash-square", "soon": "Testing soon"},
      {"name": "Image Cropper", "icon": "bi-crop", "soon": "Cropping soon"},
      {"name": "ASCII Art Generator", "icon": "bi-type", "soon": "ASCII soon"},
      {"name": "BPM Calculator", "icon": "bi-music-note-list", "soon": "Tapping soon"},
      {"name": "Text Difference Checker", "icon": "bi-file-diff", "soon": "Comparing soon"},
      {"name": "Age Calculator", "icon": "bi-person-badge", "soon": "Aging soon"},
      {"name": "Random Quote/Fact Generator", "icon": "bi-lightning", "soon": "Surprising soon"},
      {"name": "Binary/Hexadecimal Converter", "icon": "bi-123", "soon": "Converting soon"},
      {"name": "Morse Code Tools", "icon": "bi-dot", "soon": "Morsing soon"},
      {"name": "Typing Speed Test", "icon": "bi-keyboard", "soon": "Typing soon"},
      {"name": "Audio Trimmer", "icon": "bi-scissors", "soon": "Trimming soon"},
      {"name": "HTML Table Generator", "icon": "bi-table", "soon": "Tabling soon"},
      {"name": "Random Name Picker", "icon": "bi-person-lines-fill", "soon": "Picking soon"},
      {"name": "Dice", "icon": "bi-dice-5", "soon": "Rolling soon"},
      {"name": "Daily Journal Prompts", "icon": "bi-journal-richtext", "soon": "Prompting soon"},
      {"name": "Daily Affirmations", "icon": "bi-chat-left-text", "soon": "Affirming soon"},
      {"name": "Daily Challenges", "icon": "bi-lightning-charge", "soon": "Challenging soon"},
    # more upcoming tools here
]

TOOL_CATEGORIES = [
    {"key": "all", "name": "All"},
    {"key": "math", "name": "Math"},
    {"key": "science", "name": "Science"},
    {"key": "productivity", "name": "Productivity"},
    {"key": "conversion", "name": "Conversion"},
    {"key": "ai", "name": "AI"},
    {"key": "files", "name": "Files"},
    {"key": "time", "name": "Time"},
    {"key": "other", "name": "Other"},
]

ALLOWED_EXTENSIONS = {
    "image": {"jpg", "jpeg", "png", "gif", "bmp", "webp", "tiff", "svg"},
    "pdf": {"pdf"},
    "text": {"txt", "md", "csv"},
    "doc": {"docx", "doc"},
}

REVERSE_IMAGE_ENGINES = [
    {
        "name": "Google Lens",
        "url": "https://lens.google.com/upload",
        "upload": True,
        "icon": "bi-google"
    },
    {
        "name": "Yandex",
        "url": "https://yandex.com/images/search?rpt=imageview&url=",
        "upload": False,
        "icon": "bi-globe"
    },
    {
        "name": "Bing Visual",
        "url": "https://www.bing.com/images/searchbyimage?cbir=sbi&imgurl=",
        "upload": False,
        "icon": "bi-microsoft"
    },
    {
        "name": "TinEye",
        "url": "https://tineye.com/search/?url=",
        "upload": False,
        "icon": "bi-search"
    },
    {
        "name": "IQDB",
        "url": "https://iqdb.org/?url=",
        "upload": False,
        "icon": "bi-image"
    },
    {
        "name": "SauceNAO",
        "url": "https://saucenao.com/search.php?url=",
        "upload": False,
        "icon": "bi-droplet"
    },
    {
        "name": "Picsearch",
        "url": "https://www.picsearch.com/image?q=",
        "upload": False,
        "icon": "bi-image"
    },
    {
        "name": "RevIMG",
        "url": "https://www.revimg.net/search?q=",
        "upload": False,
        "icon": "bi-search"
    },
    {
        "name": "Berify",
        "url": "https://www.berify.com/reverse-image-search/?img=",
        "upload": False,
        "icon": "bi-search"
    },
    {
        "name": "Image Raider",
        "url": "https://www.imageraider.com/?q=",
        "upload": False,
        "icon": "bi-search"
    },
    {
        "name": "Search By Image",
        "url": "https://www.searchbyimage.com/?url=",
        "upload": False,
        "icon": "bi-search"
    },
    {
        "name": "Social Searcher",
        "url": "https://www.social-searcher.com/reverse-image-search/",
        "upload": True,
        "icon": "bi-globe"
    }
]

@app.route("/tools/unit-converter", methods=["GET", "POST"])
def unit_converter():
    categories = {
        "Length": {
            "units": {
                "nm": "Nanometers", "um": "Micrometers", "mm": "Millimeters", "cm": "Centimeters",
                "dm": "Decimeters", "m": "Meters", "dam": "Decameters", "hm": "Hectometers",
                "km": "Kilometers", "in": "Inches", "ft": "Feet", "yd": "Yards", "mi": "Miles",
                "nmi": "Nautical Miles", "mil": "Mils", "au": "Astronomical Units", "ly": "Light Years"
            },
            "factors": {
                "nm": 1e9, "um": 1e6, "mm": 1000, "cm": 100, "dm": 10, "m": 1, "dam": 0.1, "hm": 0.01,
                "km": 0.001, "in": 39.3700787, "ft": 3.2808399, "yd": 1.0936133, "mi": 0.000621371,
                "nmi": 0.000539957, "mil": 39370.0787, "au": 6.68458712e-12, "ly": 1.057000834e-16
            }
        },
        "Mass": {
            "units": {
                "ug": "Micrograms", "mg": "Milligrams", "cg": "Centigrams", "dg": "Decigrams", "g": "Grams",
                "dag": "Decagrams", "hg": "Hectograms", "kg": "Kilograms", "t": "Metric Tons",
                "oz": "Ounces", "lb": "Pounds", "st": "Stones", "ton_us": "US Tons", "ton_uk": "UK Tons"
            },
            "factors": {
                "ug": 1e6, "mg": 1000, "cg": 100, "dg": 10, "g": 1, "dag": 0.1, "hg": 0.01, "kg": 0.001,
                "t": 1e-6, "oz": 0.0352739619, "lb": 0.00220462262, "st": 0.000157473044, "ton_us": 1.10231131e-6, "ton_uk": 9.84206528e-7
            }
        },
        "Temperature": {
            "units": {
                "C": "Celsius", "F": "Fahrenheit", "K": "Kelvin", "R": "Rankine"
            }
            # No factors needed for temperature conversion
        },
        "Area": {
            "units": {
                "sqmm": "Square Millimeters", "sqcm": "Square Centimeters", "sqm": "Square Meters",
                "sqkm": "Square Kilometers", "sqin": "Square Inches", "sqft": "Square Feet",
                "sqyd": "Square Yards", "sqmi": "Square Miles", "acre": "Acres", "hectare": "Hectares"
            },
            "factors": {
                "sqmm": 1e6, "sqcm": 10000, "sqm": 1, "sqkm": 0.000001, "sqin": 1550.0031,
                "sqft": 10.7639104, "sqyd": 1.19599005, "sqmi": 3.86102159e-7, "acre": 0.000247105,
                "hectare": 0.0001
            }
        },
        "Volume": {
            "units": {
                "mm3": "Cubic Millimeters", "cm3": "Cubic Centimeters", "ml": "Milliliters", "cl": "Centiliters",
                "dl": "Deciliters", "l": "Liters", "m3": "Cubic Meters", "in3": "Cubic Inches",
                "ft3": "Cubic Feet", "yd3": "Cubic Yards", "gal": "US Gallons", "qt": "US Quarts",
                "pt": "US Pints", "cup": "US Cups", "floz": "US Fluid Ounces", "tbsp": "US Tablespoons",
                "tsp": "US Teaspoons"
            },
            "factors": {
                "mm3": 1e6, "cm3": 1000, "ml": 1000, "cl": 100, "dl": 10, "l": 1, "m3": 0.001,
                "in3": 61.0237441, "ft3": 0.0353146667, "yd3": 0.00130795062, "gal": 0.264172052,
                "qt": 1.05668821, "pt": 2.11337642, "cup": 4.22675284, "floz": 33.8140227,
                "tbsp": 67.6280454, "tsp": 202.884136
            }
        },
        "Speed": {
            "units": {
                "mps": "Meters/sec", "kph": "Kilometers/hour", "mph": "Miles/hour",
                "fps": "Feet/sec", "kn": "Knots"
            },
            "factors": {
                "mps": 1, "kph": 3.6, "mph": 2.23693629, "fps": 3.2808399, "kn": 1.94384449
            }
        },
        "Time": {
            "units": {
                "ns": "Nanoseconds", "us": "Microseconds", "ms": "Milliseconds", "s": "Seconds",
                "min": "Minutes", "hr": "Hours", "day": "Days", "wk": "Weeks", "mo": "Months (30d)", "yr": "Years"
            },
            "factors": {
                "ns": 1e9, "us": 1e6, "ms": 1000, "s": 1, "min": 1/60, "hr": 1/3600, "day": 1/86400,
                "wk": 1/604800, "mo": 1/2.592e6, "yr": 1/3.154e7
            }
        },
        "Data": {
            "units": {
                "b": "Bits", "B": "Bytes", "KB": "Kilobytes", "MB": "Megabytes", "GB": "Gigabytes",
                "TB": "Terabytes", "PB": "Petabytes", "EB": "Exabytes"
            },
            "factors": {
                "b": 8e9, "B": 1e9, "KB": 1e6, "MB": 1000, "GB": 1, "TB": 0.001, "PB": 1e-6, "EB": 1e-9
            }
        },
        "Pressure": {
            "units": {
                "pa": "Pascals", "kpa": "Kilopascals", "mpa": "Megapascals", "bar": "Bar",
                "psi": "Pounds/sq inch", "atm": "Atmospheres", "mmhg": "Millimeters Hg", "inhg": "Inches Hg"
            },
            "factors": {
                "pa": 100000, "kpa": 100, "mpa": 0.1, "bar": 1, "psi": 14.5037738, "atm": 0.986923267,
                "mmhg": 750.061683, "inhg": 29.5299831
            }
        },
        "Energy": {
            "units": {
                "j": "Joules", "kj": "Kilojoules", "mj": "Megajoules", "cal": "Calories",
                "kcal": "Kilocalories", "wh": "Watt-hours", "kwh": "Kilowatt-hours", "ev": "Electronvolts",
                "btu": "BTU"
            },
            "factors": {
                "j": 1, "kj": 0.001, "mj": 1e-6, "cal": 0.239005736, "kcal": 0.000239006,
                "wh": 0.000277778, "kwh": 2.7778e-7, "ev": 6.242e18, "btu": 0.000947817
            }
        },
        "Power": {
            "units": {
                "w": "Watts", "kw": "Kilowatts", "mw": "Megawatts", "hp": "Horsepower"
            },
            "factors": {
                "w": 1, "kw": 0.001, "mw": 1e-6, "hp": 0.00134102209
            }
        },
        "Angle": {
            "units": {
                "deg": "Degrees", "rad": "Radians", "grad": "Gradians", "arcmin": "Arcminutes", "arcsec": "Arcseconds"
            },
            "factors": {
                "deg": 1, "rad": 0.0174532925, "grad": 1.11111111, "arcmin": 60, "arcsec": 3600
            }
        },
        "Frequency": {
            "units": {
                "hz": "Hertz", "khz": "Kilohertz", "mhz": "Megahertz", "ghz": "Gigahertz"
            },
            "factors": {
                "hz": 1, "khz": 0.001, "mhz": 1e-6, "ghz": 1e-9
            }
        },
        "Force": {
            "units": {
                "n": "Newtons", "kn": "Kilonewtons", "mn": "Meganewtons", "gf": "Gram-force",
                "kgf": "Kilogram-force", "lbf": "Pound-force"
            },
            "factors": {
                "n": 1, "kn": 0.001, "mn": 1e-6, "gf": 101.971621, "kgf": 0.101971621, "lbf": 0.224808943
            }
        }
    }

    result = None
    value = None
    from_unit = None
    to_unit = None
    category = request.form.get("category", "Length")
    units = categories[category]["units"]

    if request.method == "POST":
        value = request.form.get("value")
        from_unit = request.form.get("from_unit")
        to_unit = request.form.get("to_unit")
        try:
            value = float(value)
            if category == "Temperature":
                if from_unit == to_unit:
                    result = value
                elif from_unit == "C" and to_unit == "F":
                    result = value * 9/5 + 32
                elif from_unit == "F" and to_unit == "C":
                    result = (value - 32) * 5/9
                elif from_unit == "C" and to_unit == "K":
                    result = value + 273.15
                elif from_unit == "K" and to_unit == "C":
                    result = value - 273.15
                elif from_unit == "F" and to_unit == "K":
                    result = (value - 32) * 5/9 + 273.15
                elif from_unit == "K" and to_unit == "F":
                    result = (value - 273.15) * 9/5 + 32
                elif from_unit == "C" and to_unit == "R":
                    result = (value + 273.15) * 9/5
                elif from_unit == "R" and to_unit == "C":
                    result = value * 5/9 - 273.15
                elif from_unit == "F" and to_unit == "R":
                    result = value + 459.67
                elif from_unit == "R" and to_unit == "F":
                    result = value - 459.67
                elif from_unit == "K" and to_unit == "R":
                    result = value * 9/5
                elif from_unit == "R" and to_unit == "K":
                    result = value * 5/9
                else:
                    result = "Invalid units"
            else:
                factors = categories[category]["factors"]
                if from_unit in factors and to_unit in factors:
                    # Convert to base, then to target
                    base = value / factors[from_unit]
                    result = base * factors[to_unit]
                else:
                    result = "Invalid units"
        except Exception as e:
            result = f"Error: {e}"

    return render_template(
        "tools/unit_converter.html",
        result=result,
        value=value,
        from_unit=from_unit,
        to_unit=to_unit,
        category=category,
        categories=categories,
        units=units
    )

import requests

@app.route("/tools/currency-converter", methods=["GET", "POST"])
def currency_converter():
    currencies = []
    result = None
    amount = None
    from_currency = None
    to_currency = None
    try:
        resp = requests.get("https://api.frankfurter.app/currencies")
        currencies = sorted(resp.json().items())
    except Exception:
        currencies = [("USD", "US Dollar"), ("EUR", "Euro")]
    if request.method == "POST":
        amount = float(request.form.get("amount", 0))
        from_currency = request.form.get("from_currency")
        to_currency = request.form.get("to_currency")
        if from_currency and to_currency and amount:
            resp = requests.get(f"https://api.frankfurter.app/latest?amount={amount}&from={from_currency}&to={to_currency}")
            data = resp.json()
            result = data["rates"].get(to_currency)
    return render_template(
        "tools/currency_converter.html",
        result=result,
        amount=amount,
        from_currency=from_currency,
        to_currency=to_currency,
        currencies=currencies
    )

@app.route("/tools/scientific-calculator")
def scientific_calculator():
    return render_template("tools/scientific_calculator.html")

@app.route("/tools/todo", methods=["GET", "POST"])
@login_required
def todo():
    if request.method == "POST":
        content = request.form.get("content")
        due_date = request.form.get("due_date")
        todo = Todo(user_id=session["user_id"], content=content, due_date=due_date)
        db.session.add(todo)
        db.session.commit()
    todos = Todo.query.filter_by(user_id=session["user_id"]).order_by(Todo.due_date).all()
    return render_template("tools/todo.html", todos=todos)

@app.route("/tools/notes", methods=["GET", "POST"])
@login_required
def notes():
    if request.method == "POST":
        content = request.form.get("content")
        note = Note(user_id=session["user_id"], content=content)
        db.session.add(note)
        db.session.commit()
    notes = Note.query.filter_by(user_id=session["user_id"]).order_by(Note.created_at.desc()).all()
    return render_template("tools/notes.html", notes=notes)

@app.route("/export/notes")
@login_required
def export_notes():
    notes = Note.query.filter_by(user_id=session["user_id"]).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["content", "created_at"])
    for note in notes:
        writer.writerow([note.content, note.created_at])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), as_attachment=True, download_name="notes.csv", mimetype="text/csv")

@app.route("/export/todos")
@login_required
def export_todos():
    todos = Todo.query.filter_by(user_id=session["user_id"]).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["content", "due_date", "completed", "created_at"])
    for todo in todos:
        writer.writerow([todo.content, todo.due_date, todo.completed, todo.created_at])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), as_attachment=True, download_name="todos.csv", mimetype="text/csv")

@app.route("/tools")
def tools():
    logged_in = bool(session.get("user_id"))
    query = request.args.get("q", "").strip().lower()
    filtered_tools = TOOLS
    if query:
        filtered_tools = [tool for tool in TOOLS if query in tool["name"].lower()]
    return render_template(
        "tools.html",
        tools=filtered_tools,
        upcoming_tools=UPCOMING_TOOLS,
        wip_tools=WIP_TOOLS,
        logged_in=logged_in,
        query=query,
        tool_categories=TOOL_CATEGORIES
    )

@app.route("/login/google")
def login_google():
    if not google.authorized:
        flash("Google authorization failed. Please try again.", "danger")
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "danger")
        return redirect("/login")
    info = resp.json()
    google_id = info.get("id")
    email = info.get("email")
    name = info.get("name")
    avatar_url = info.get("picture")
    if not email:
        flash("Google account did not return an email address.", "danger")
        return redirect("/login")

    # If user is logged in, link Google account
    if session.get("user_id"):
        user = User.query.get(session["user_id"])
        if user.google_id and user.google_id != google_id:
            flash("This account is already linked to another Google account.", "danger")
        else:
            user.google_id = google_id
            if avatar_url:
                user.avatar_url = avatar_url
            db.session.commit()
            flash("Google account linked!", "success")
        return redirect("/profile")

    # If not logged in, try to find user by google_id or email
    user = User.query.filter((User.google_id == google_id) | (User.email == email)).first()
    if user:
        if not user.google_id:
            user.google_id = google_id
            db.session.commit()
        session["user_id"] = user.id
        flash("Logged in with Google!", "success")
        return redirect("/")
    else:
        # Register new user with Google info
        username = email.split("@")[0]
        # Ensure username is unique
        base_username = username
        i = 1
        while User.query.filter_by(username=username).first():
            username = f"{base_username}{i}"
            i += 1
        user = User(
            username=username,
            email=email,
            google_id=google_id,
            avatar_url=avatar_url,
            hash=generate_password_hash(os.urandom(16).hex()),  # Dummy password
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(user)
        db.session.commit()
        session["user_id"] = user.id
        flash("Registered and logged in with Google!", "success")
        return redirect("/")

@app.route("/notifications")
@login_required
def notifications():
    notes = Notification.query.filter_by(user_id=session["user_id"]).order_by(Notification.created_at.desc()).all()
    return render_template("notifications.html", notes=notes)

@app.route("/admin")
@login_required
def admin():
    user = User.query.get(session["user_id"])
    if not user.is_admin:
        abort(403)
    users = User.query.all()
    feedbacks = Feedback.query.order_by(Feedback.created_at.desc()).all()
    return render_template("admin.html", users=users, feedbacks=feedbacks)

@app.route("/admin/promote/<int:user_id>")
@login_required
def admin_promote(user_id):
    user = User.query.get(session["user_id"])
    if not user.is_admin:
        abort(403)
    target = User.query.get(user_id)
    if target:
        target.is_admin = True
        db.session.commit()
        flash("User promoted to admin.", "success")
    return redirect("/admin")

@app.route("/admin/demote/<int:user_id>")
@login_required
def admin_demote(user_id):
    user = User.query.get(session["user_id"])
    if not user.is_admin:
        abort(403)
    target = User.query.get(user_id)
    if target and target.id != user.id:
        target.is_admin = False
        db.session.commit()
        flash("User demoted.", "warning")
    return redirect("/admin")

@app.route("/admin/delete/<int:user_id>")
@login_required
def admin_delete(user_id):
    user = User.query.get(session["user_id"])
    if not user.is_admin:
        abort(403)
    target = User.query.get(user_id)
    if target and target.id != user.id:
        db.session.delete(target)
        db.session.commit()
        flash("User deleted.", "danger")
    return redirect("/admin")

@app.route("/api/user/<int:user_id>")
def api_user(user_id):
    user = User.query.get(user_id)
    return {"username": user.username, "email": user.email}

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# --- OTP Helper Functions ---
def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(user, otp):
    msg = Message(
        subject="Your OTP Verification Code",
        recipients=[user.email],
        body=f"Your OTP code is: {otp}\nThis code will expire in 10 minutes."
    )
    mail.send(msg)

@app.route("/tools/calculator", methods=["GET", "POST"])
def calculator():
    result = None
    if request.method == "POST":
        try:
            a = float(request.form.get("a"))
            b = float(request.form.get("b"))
            op = request.form.get("op")
            if op == "+":
                result = a + b
            elif op == "-":
                result = a - b
            elif op == "*":
                result = a * b
            elif op == "/":
                result = a / b if b != 0 else "Error: Division by zero"
            else:
                result = "Invalid operation"
        except Exception as e:
            result = f"Error: {e}"
    return render_template("tools/calculator.html", result=result)

@app.route("/tools/file-converter", methods=["GET", "POST"])
def file_converter():
    result = []
    zip_id = None
    categories = {
        "images": {
            "label": "Pictures",
            "exts": [
                "png", "jpg", "jpeg", "bmp", "gif", "webp", "tiff", "ico", "svg", "heic", "raw"
            ]
        },
        "docs": {
            "label": "Documents",
            "exts": [
                "pdf", "txt", "docx", "doc", "md", "csv", "rtf", "odt", "epub", "html", "xml", "json", "xls", "xlsx", "ppt", "pptx"
            ]
        },
        "audio": {
            "label": "Audio",
            "exts": [
                "mp3", "wav", "ogg", "flac", "aac", "m4a", "wma", "opus", "amr", "aiff"
            ]
        },
        "video": {
            "label": "Video",
            "exts": [
                "mp4", "avi", "mov", "wmv", "flv", "mkv", "webm", "mpeg", "mpg", "3gp"
            ]
        },
        "archives": {
            "label": "Archives",
            "exts": [
                "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "iso"
            ]
        },
        "fonts": {
            "label": "Fonts",
            "exts": [
                "ttf", "otf", "woff", "woff2", "eot"
            ]
        },
        "code": {
            "label": "Code",
            "exts": [
                "py", "js", "java", "cpp", "c", "cs", "rb", "php", "go", "rs", "swift", "kt", "ts", "html", "css", "json", "xml", "sh", "bat"
            ]
        },
        "ebooks": {
            "label": "Ebooks",
            "exts": [
                "epub", "mobi", "azw3", "fb2", "pdf"
            ]
        },
        "presentations": {
            "label": "Presentations",
            "exts": [
                "ppt", "pptx", "odp", "pdf"
            ]
        },
        "spreadsheets": {
            "label": "Spreadsheets",
            "exts": [
                "xls", "xlsx", "ods", "csv", "tsv"
            ]
        },
        # Add more here
    }
    # Prefer POST form value, fallback to GET param, default to 'images'
    selected_category = request.form.get("category") or request.args.get("category") or "images"
    if request.method == "POST":
        files = request.files.getlist("files")
        target_format = request.form.get("target_format")
        converted_files = []
        for file in files:
            filename = secure_filename(file.filename)
            ext = filename.rsplit('.', 1)[-1].lower()
            if selected_category == "images" and ext in categories["images"]["exts"] and target_format in categories["images"]["exts"]:
                try:
                    img = Image.open(file)
                    out_filename = filename.rsplit('.', 1)[0] + "." + target_format
                    memfile = io.BytesIO()
                    img.save(memfile, target_format.upper())
                    memfile.seek(0)
                    converted_files.append((out_filename, base64.b64encode(memfile.read()).decode("utf-8")))
                    result.append({"type": "success", "file": out_filename})
                except Exception as e:
                    result.append({"type": "error", "msg": f"Error converting {filename}: {e}"})
            else:
                result.append({"type": "error", "msg": f"Unsupported file: {filename}"})
        # Store converted files in session for temporary download
        if converted_files:
            zip_id = uuid.uuid4().hex
            session[f"zip_{zip_id}"] = converted_files
    zip_url = url_for('download_zip', zip_id=zip_id) if zip_id else None
    return render_template(
        "tools/file_converter.html",
        result=result,
        categories=categories,
        selected_category=selected_category,
        zip_url=zip_url
    )

@app.route("/api/translate", methods=["POST"])
def api_translate():
    from deep_translator import GoogleTranslator
    text = request.form.get("text", "")
    src = request.form.get("src", "auto")
    dest = request.form.get("dest", "en")
    result = ""
    detected = ""
    if text:
        try:
            if src == "auto":
                detected = GoogleTranslator(source="auto", target=dest).detect(text)
                src = detected
            result = GoogleTranslator(source=src, target=dest).translate(text)
        except Exception as e:
            result = f"Error: {e}"
    return jsonify({"result": result, "detected": detected})

@app.route("/tools/translator", methods=["GET", "POST"])
def translator():
    text = request.form.get("text", "")
    src = request.form.get("src", "auto")
    dest = request.form.get("dest", "en")
    result = ""
    # Use a static mapping for language codes to names
    language_map = {
        "af": "Afrikaans", "sq": "Albanian", "am": "Amharic", "ar": "Arabic", "hy": "Armenian", "az": "Azerbaijani",
        "eu": "Basque", "be": "Belarusian", "bn": "Bengali", "bs": "Bosnian", "bg": "Bulgarian", "ca": "Catalan",
        "ceb": "Cebuano", "ny": "Chichewa", "zh-cn": "Chinese (Simplified)", "zh-tw": "Chinese (Traditional)",
        "co": "Corsican", "hr": "Croatian", "cs": "Czech", "da": "Danish", "nl": "Dutch", "en": "English",
        "eo": "Esperanto", "et": "Estonian", "tl": "Filipino", "fi": "Finnish", "fr": "French", "fy": "Frisian",
        "gl": "Galician", "ka": "Georgian", "de": "German", "el": "Greek", "gu": "Gujarati", "ht": "Haitian Creole",
        "ha": "Hausa", "haw": "Hawaiian", "iw": "Hebrew", "hi": "Hindi", "hmn": "Hmong", "hu": "Hungarian",
        "is": "Icelandic", "ig": "Igbo", "id": "Indonesian", "ga": "Irish", "it": "Italian", "ja": "Japanese",
        "jw": "Javanese", "kn": "Kannada", "kk": "Kazakh", "km": "Khmer", "ko": "Korean", "ku": "Kurdish (Kurmanji)",
        "ky": "Kyrgyz", "lo": "Lao", "la": "Latin", "lv": "Latvian", "lt": "Lithuanian", "lb": "Luxembourgish",
        "mk": "Macedonian", "mg": "Malagasy", "ms": "Malay", "ml": "Malayalam", "mt": "Maltese", "mi": "Maori",
        "mr": "Marathi", "mn": "Mongolian", "my": "Myanmar (Burmese)", "ne": "Nepali", "no": "Norwegian",
        "ps": "Pashto", "fa": "Persian", "pl": "Polish", "pt": "Portuguese", "pa": "Punjabi", "ro": "Romanian",
        "ru": "Russian", "sm": "Samoan", "gd": "Scots Gaelic", "sr": "Serbian", "st": "Sesotho", "sn": "Shona",
        "sd": "Sindhi", "si": "Sinhala", "sk": "Slovak", "sl": "Slovenian", "so": "Somali", "es": "Spanish",
        "su": "Sundanese", "sw": "Swahili", "sv": "Swedish", "tg": "Tajik", "ta": "Tamil", "te": "Telugu",
        "th": "Thai", "tr": "Turkish", "uk": "Ukrainian", "ur": "Urdu", "uz": "Uzbek", "vi": "Vietnamese",
        "cy": "Welsh", "xh": "Xhosa", "yi": "Yiddish", "yo": "Yoruba", "zu": "Zulu"
    }
    language_choices = sorted(language_map.items(), key=lambda x: x[1])
    if text:
        try:
            result = GoogleTranslator(source=src, target=dest).translate(text)
        except Exception as e:
            result = f"Error: {e}"
    return render_template(
        "tools/translator.html",
        text=text,
        src=src,
        dest=dest,
        result=result,
        language_choices=language_choices
    )

@app.route("/tools/search", methods=["GET", "POST"])
def search():
    search_engines = [
        {"key": "google", "name": "Google", "icon": "bi-google", "url": "https://www.google.com/search?q="},
        {"key": "bing", "name": "Bing", "icon": "bi-microsoft", "url": "https://www.bing.com/search?q="},
        {"key": "duckduckgo", "name": "DuckDuckGo", "icon": "bi-duck", "url": "https://duckduckgo.com/?q="},
        {"key": "yahoo", "name": "Yahoo", "icon": "bi-yahoo", "url": "https://search.yahoo.com/search?p="},
        {"key": "baidu", "name": "Baidu", "icon": "bi-globe", "url": "https://www.baidu.com/s?wd="},
        {"key": "yandex", "name": "Yandex", "icon": "bi-globe", "url": "https://yandex.com/search/?text="},
        {"key": "startpage", "name": "StartPage", "icon": "bi-shield-lock", "url": "https://www.startpage.com/do/search?q="},
        {"key": "qwant", "name": "Qwant", "icon": "bi-search", "url": "https://www.qwant.com/?q="},
        {"key": "mojeek", "name": "Mojeek", "icon": "bi-search", "url": "https://www.mojeek.com/search?q="},
        {"key": "gigablast", "name": "Gigablast", "icon": "bi-search", "url": "https://www.gigablast.com/search?q="},
        # Add more as needed
    ]
    query = request.form.get("query", "")
    return render_template("tools/search.html", search_engines=search_engines, query=query)

# Example daily quotes/questions (replace with DB or API as needed)
DAILY_QUOTES = [
    "Stay positive, work hard, make it happen.",
    "Success is not for the lazy.",
    "Dream big and dare to fail.",
]
DAILY_QUESTIONS = [
    "What is one thing you want to accomplish today?",
    "What are you grateful for today?",
    "How will you challenge yourself today?",
]

@app.route("/tools/file-converter/download/<zip_id>")
def download_zip(zip_id):
    files = session.get(f"zip_{zip_id}")
    if not files:
        abort(404)
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zipf:
        for fname, b64data in files:
            zipf.writestr(fname, base64.b64decode(b64data))
    zip_buffer.seek(0)
    # Remove from session after download to free memory
    session.pop(f"zip_{zip_id}", None)
    return send_file(
        zip_buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name="converted_files.zip"
    )

@app.route("/tools/file-converter/download-file/<zip_id>/<filename>")
def download_file(zip_id, filename):
    files = session.get(f"zip_{zip_id}")
    if not files:
        abort(404)
    for fname, b64data in files:
        if fname == filename:
            file_bytes = base64.b64decode(b64data)
            return send_file(
                io.BytesIO(file_bytes),
                as_attachment=True,
                download_name=fname
            )
    abort(404)

@app.route("/tools/pomodoro")
def pomodoro():
    return render_template("tools/pomodoro.html")

@app.route("/tools/stopwatch", methods=["GET", "POST"])
def stopwatch():
    if "stopwatches" not in session:
        session["stopwatches"] = []
    stopwatches = session["stopwatches"]
    if request.method == "POST":
        name = request.form.get("stopwatch_name", f"Stopwatch {len(stopwatches)+1}")
        stopwatches.append({"name": name, "id": str(uuid.uuid4())})
        session["stopwatches"] = stopwatches
    return render_template("tools/stopwatch.html", stopwatches=stopwatches)

@app.route("/tools/timer", methods=["GET", "POST"])
def timer():
    if "timers" not in session:
        session["timers"] = []
    timers = session["timers"]
    error = None
    if request.method == "POST":
        # Handle timer deletion
        if request.form.get("delete_timer"):
            del_id = request.form.get("delete_timer")
            timers = [t for t in timers if str(t.get("id")) != str(del_id)]
            session["timers"] = timers
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return ("", 204)
            else:
                return redirect(request.url)
        try:
            name = request.form.get("timer_name", "Timer").strip() or "Timer"
            minutes_raw = request.form.get("minutes", "0")
            seconds_raw = request.form.get("seconds", "0")
            minutes = int(minutes_raw) if minutes_raw.isdigit() else 0
            seconds = int(seconds_raw) if seconds_raw.isdigit() else 0
            if minutes < 0 or seconds < 0 or seconds > 59:
                error = _("Please enter valid non-negative values. Seconds must be 0-59.")
            elif minutes == 0 and seconds == 0:
                error = _("Timer must be at least 1 second.")
            else:
                timers.append({"name": name, "minutes": minutes, "seconds": seconds, "id": str(uuid.uuid4())})
                session["timers"] = timers
        except Exception:
            error = _("Invalid input. Please enter numbers only.")
    return render_template("tools/timer.html", timers=timers, error=error)

@app.route("/tools/world-clock")
def world_clock():
    return render_template("tools/world_clock.html", bigdatacloud_api_key=BIGDATACLOUD_API_KEY)

@app.route("/passkey/register/begin", methods=["POST"])
@login_required
def passkey_register_begin():
    user = User.query.get(session["user_id"])
    user_id = str(user.id).encode()
    registration_data, state = fido2_server.register_begin(
        {
            "id": user_id,
            "name": user.username,
            "displayName": user.username,
        },
        user.passkeys or [],
        user_verification="preferred"
    )
    session["fido2_state"] = state
    return cbor.encode(registration_data)

@app.route("/passkey/register/complete", methods=["POST"])
@login_required
def passkey_register_complete():
    user = User.query.get(session["user_id"])
    data = cbor.decode(request.get_data())
    state = session.pop("fido2_state")
    auth_data = fido2_server.register_complete(state, data["clientDataJSON"], data["attestationObject"])
    # Store credential
    creds = user.passkeys or []
    creds.append(auth_data.credential_data.__dict__)
    user.passkeys = creds
    db.session.commit()
    return jsonify({"status": "ok"})

@app.route("/passkey/login/begin", methods=["POST"])
def passkey_login_begin():
    identifier = request.json.get("identifier")
    user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
    if not user or not user.passkeys:
        return jsonify({"error": "No passkey registered"}), 400
    auth_data, state = fido2_server.authenticate_begin(user.passkeys)
    session["fido2_login_state"] = state
    session["fido2_login_user"] = user.id
    return cbor.encode(auth_data)

@app.route("/passkey/login/complete", methods=["POST"])
def passkey_login_complete():
    user = User.query.get(session.get("fido2_login_user"))
    if not user:
        return jsonify({"error": "User not found"}), 400
    data = cbor.decode(request.get_data())
    state = session.pop("fido2_login_state")
    creds = user.passkeys
    fido2_server.authenticate_complete(state, creds, data["credentialId"], data["clientDataJSON"], data["authenticatorData"], data["signature"])
    session["user_id"] = user.id
    return jsonify({"status": "ok"})

@app.route("/tools/periodic-table")
def periodic_table():
    import json
    import requests  # Import the requests library

    try:
        response = requests.get("https://raw.githubusercontent.com/Bowserinator/Periodic-Table-JSON/master/PeriodicTableJSON.json", timeout=5)  # Fetch the JSON data
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()  # Parse the JSON data from the response
        elements = data["elements"]
    except requests.exceptions.RequestException as e:
        # Handle potential network errors (e.g., connection refused, timeout)
        return f"Error fetching data: {e}", 500
    except json.JSONDecodeError as e:
        # Handle potential JSON parsing errors
        return f"Error parsing JSON: {e}", 500

    category_colors = {
        "alkali metal": "#ffb74d",
        "alkaline earth metal": "#ffd54f",
        "transition metal": "#90caf9",
        "post-transition metal": "#b0bec5",
        "metalloid": "#a5d6a7",
        "nonmetal": "#fff176",
        "noble gas": "#ce93d8",
        "halogen": "#f06292",
        "lanthanide": "#80cbc4",
        "actinide": "#bcaaa4",
        "unknown": "#eeeeee"
    }
    return render_template("tools/periodic_table.html", elements=elements, category_colors=category_colors)

@app.route("/tools/image-metadata", methods=["GET", "POST"])
def image_metadata():
    metadata = {}
    error = None
    image_preview = None
    if request.method == "POST":
        file = request.files.get("image")
        if file:
            try:
                img = Image.open(file)
                # Save preview
                preview_io = io.BytesIO()
                img.thumbnail((300, 300))
                img.save(preview_io, format="PNG")
                preview_io.seek(0)
                image_preview = base64.b64encode(preview_io.read()).decode("utf-8")
                # Basic info
                file.seek(0, os.SEEK_END)
                size = file.tell()
                file.seek(0)
                metadata["Format"] = img.format
                metadata["Mode"] = img.mode
                metadata["Dimensions"] = f"{img.width} x {img.height}"
                metadata["File Size"] = f"{size/1024:.2f} KB"
                exif_data = img.getexif()
                if exif_data:
                    from PIL.ExifTags import TAGS
                    for tag_id, value in exif_data.items():
                        tag = TAGS.get(tag_id, tag_id)
                        metadata[str(tag)] = value
                if not metadata:
                    metadata["Info"] = "No metadata found."
            except Exception as e:
                error = f"Error reading image: {e}"
        else:
            error = "No file uploaded."
    return render_template("tools/image_metadata.html", metadata=metadata, error=error, image_preview=image_preview)

short_urls = {}

@app.route("/tools/url-shortener", methods=["GET", "POST"])
def url_shortener():
    short_url = None
    error = None
    if request.method == "POST":
        original = request.form.get("original")
        custom = request.form.get("custom")
        expiry_hours = int(request.form.get("expiry", 24))
        expiry = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)
        if not original or not custom:
            error = "Both fields are required."
        elif custom in short_urls and short_urls[custom][1] > datetime.now(timezone.utc):
            error = "Custom short URL already taken."
        else:
            short_urls[custom] = (original, expiry)
            short_url = request.host_url + "s/" + custom
    return render_template("tools/url_shortener.html", short_url=short_url, error=error)

@app.route("/s/<custom>")
def redirect_short(custom):
    url = short_urls.get(custom)
    if url:
        return redirect(url)
    return "Short URL not found", 404

redirects = {}

@app.route("/tools/url-redirects", methods=["GET", "POST"])
def url_redirects():
    message = None
    error = None
    if request.method == "POST":
        path = request.form.get("path", "").strip()
        target = request.form.get("target", "").strip()
        if not path or not target:
            error = "Both fields are required."
        elif path in redirects:
            error = "This path already exists."
        else:
            redirects[path] = target
            message = f"Redirect /go/{path} → {target} created."
    return render_template("tools/url_redirects.html", message=message, error=error, redirects=redirects)

@app.route("/go/<path>")
def go_redirect(path):
    url = redirects.get(path)
    if url:
        return redirect(url)
    return "Redirect not found", 404

@app.route("/tools/ai-prompt", methods=["GET", "POST"])
def ai_prompt():
    result = None
    prompt = ""
    if request.method == "POST":
        prompt = request.form.get("prompt", "").strip()
        if not prompt:
            result = "Please enter a prompt."
        else:
            try:
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=256,
                    temperature=0.7,
                )
                result = response.choices[0].message.content
            except Exception as e:
                result = f"Error: {e}"
    return render_template("tools/ai_prompt.html", prompt=prompt, result=result)

@app.route("/tools/ai-summarizer", methods=["GET", "POST"])
def ai_summarizer():
    summary = None
    text = ""
    if request.method == "POST":
        text = request.form.get("text", "")
        if text:
            try:
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "Summarize the following text in a concise way."},
                        {"role": "user", "content": text}
                    ],
                    max_tokens=128,
                    temperature=0.5,
                )
                summary = response.choices[0].message.content
            except Exception as e:
                summary = f"Error: {e}"
    return render_template("tools/ai-summarizer.html", summary=summary, text=text)

@app.route("/tools/ai-code-explainer", methods=["GET", "POST"])
def ai_code_explainer():
    explanation = None
    code = ""
    if request.method == "POST":
        code = request.form.get("code", "")
        if code:
            try:
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "Explain what the following code does in simple terms."},
                        {"role": "user", "content": code}
                    ],
                    max_tokens=256,
                    temperature=0.5,
                )
                explanation = response.choices[0].message.content
            except Exception as e:
                explanation = f"Error: {e}"
    return render_template("tools/ai_code_explainer.html", explanation=explanation, code=code)

@app.route("/tools/integration-calculator", methods=["GET", "POST"])
def integration_calculator():
    result = None
    expr = ""
    var = "x"
    lower = ""
    upper = ""
    if request.method == "POST":
        expr = request.form.get("expr", "")
        var = request.form.get("var", "x")
        lower = request.form.get("lower", "")
        upper = request.form.get("upper", "")
        try:
            x = symbols(var)
            parsed = sympify(expr)
            if lower and upper:
                result = integrate(parsed, (x, float(lower), float(upper)))
            else:
                result = integrate(parsed, x)
        except Exception as e:
            result = f"Error: {e}"
    return render_template("tools/integration_calculator.html", result=result, expr=expr, var=var, lower=lower, upper=upper)

@app.route("/tools/differentiation-calculator", methods=["GET", "POST"])
def differentiation_calculator():
    result = None
    expr = ""
    var = "x"
    if request.method == "POST":
        expr = request.form.get("expr", "")
        var = request.form.get("var", "x")
        try:
            x = symbols(var)
            parsed = sympify(expr)
            result = diff(parsed, x)
        except Exception as e:
            result = f"Error: {e}"
   
    return render_template("tools/differentiation_calculator.html", result=result, expr=expr, var=var)

@app.route("/tools/equation-solver", methods=["GET", "POST"])
def equation_solver():
    result = None
    eqn = ""
    var = "x"
    if request.method == "POST":
        eqn = request.form.get("eqn", "")
        var = request.form.get("var", "x")
        try:
            x = symbols(var)
            eq = Eq(sympify(eqn), 0)
            result = solve(eq, x)
        except Exception as e:
            result = f"Error: {e}"
    return render_template("tools/equation_solver.html", result=result, eqn=eqn, var=var)

@app.route("/tools/matrix-calculator", methods=["GET", "POST"])
def matrix_calculator():
    from sympy import Matrix
    result = None
    num_matrices = int(request.form.get("num_matrices", 2))
    rows = int(request.form.get("rows", 2))
    cols = int(request.form.get("cols", 2))
    operation = request.form.get("operation", "add")
    matrices = []
    for idx in range(num_matrices):
        matrix = []
        for i in range(rows):
            row = []
            for j in range(cols):
                val = request.form.get(f"m{idx}_{i}_{j}", "0")
                if isinstance(val, dict):
                    print(f"Matrix input error: got dict at m{idx}_{i}_{j}: {val}")
                    val = 0.0
                row.append(val)
            matrix.append(row)
        matrices.append(matrix)
    if request.method == "POST":
        try:
            mats = [Matrix([[float(x) for x in row] for row in m]) for m in matrices]
            if operation == "add":
                result = sum(mats)
            elif operation == "subtract":
                result = mats[0]
                for m in mats[1:]:
                    result -= m
            elif operation == "multiply":
                result = mats[0]
                for m in mats[1:]:
                    result *= m
            elif operation == "determinant":
                result = mats[0].det()
            elif operation == "inverse":
                result = mats[0].inv()
            elif operation == "transpose":
                result = mats[0].T
            elif operation == "rank":
                result = mats[0].rank()
            elif operation == "trace":
                result = mats[0].trace()
            elif operation == "eigenvals":
                result = mats[0].eigenvals()
            elif operation == "eigenvects":
                result = mats[0].eigenvects()
            else:
                result = "Invalid operation"
        except Exception as e:
            result = f"Error: {e}"
    return render_template(
        "tools/matrix_calculator.html",
        result=result,
        num_matrices=num_matrices,
        rows=rows,
        cols=cols,
        matrices=matrices,
        operation=operation
    )

@app.route("/tools/complex-calculator", methods=["GET", "POST"])
def complex_calculator():
    result = None
    a = ""
    b = ""
    op = "+"
    if request.method == "POST":
        a = request.form.get("a", "")
        b = request.form.get("b", "")
        op = request.form.get("op", "+")
        try:
            ca = complex(a.replace("i", "j"))
            cb = complex(b.replace("i", "j"))
            if op == "+":
                result = ca + cb
            elif op == "-":
                result = ca - cb
            elif op == "*":
                result = ca * cb
            elif op == "/":
                result = ca / cb
            else:
                result = "Invalid operation"
        except Exception as e:
            result = f"Error: {e}"
    return render_template("tools/complex_calculator.html", result=result, a=a, b=b, op=op)

@app.route("/tools/polynomial-calculator", methods=["GET", "POST"])
def polynomial_calculator():
    result = None
    coeffs = ""
    x_val = ""
    action = "roots"
    if request.method == "POST":
        coeffs = request.form.get("coeffs", "")
        x_val = request.form.get("x_val", "")
        action = request.form.get("action", "roots")
        try:
            coeff_list = [float(c) for c in coeffs.split(",")]
            x = symbols("x")
            poly = sum(c * x**i for i, c in enumerate(reversed(coeff_list)))
            if action == "roots":
                result = solve(poly, x)
            elif action == "evaluate":
                result = poly.subs(x, float(x_val))
            elif action == "derivative":
                result = diff(poly, x)
            elif action == "integral":
                result = integrate(poly, x)
            else:
                result = "Invalid action"
        except Exception as e:
            result = f"Error: {e}"
    return render_template("tools/polynomial_calculator.html", result=result, coeffs=coeffs, x_val=x_val, action=action)

@app.route("/tools/statistics-calculator", methods=["GET", "POST"])
def statistics_calculator():
    import statistics
    result = None
    data = ""
    stat = "mean"
    if request.method == "POST":
        data = request.form.get("data", "")
        stat = request.form.get("stat", "mean")
        try:
            nums = [float(x) for x in data.replace(";", ",").split(",") if x.strip()]
            if stat == "mean":
                result = statistics.mean(nums)
            elif stat == "median":
                result = statistics.median(nums)
            elif stat == "mode":
                result = statistics.mode(nums)
            elif stat == "stdev":
                result = statistics.stdev(nums)
            elif stat == "variance":
                result = statistics.variance(nums)
            else:
                result = "Invalid statistic"
        except Exception as e:
            result = f"Error: {e}"
    return render_template("tools/statistics_calculator.html", result=result, data=data, stat=stat)

@app.route("/tools/base-converter", methods=["GET", "POST"])
def base_converter():
    result = None
    number = ""
    from_base = "10"
    to_base = "2"
    if request.method == "POST":
        number = request.form.get("number", "")
        from_base = request.form.get("from_base", "10")
        to_base = request.form.get("to_base", "2")
        try:
            n = int(number, int(from_base))
            if to_base == "2":
                result = bin(n)
            elif to_base == "8":
                result = oct(n)
            elif to_base == "10":
                result = str(n)
            elif to_base == "16":
                result = hex(n)
            else:
                result = format(n, f"b")  # fallback
        except Exception as e:
            result = f"Error: {e}"
    return render_template("tools/base_converter.html", result=result, number=number, from_base=from_base, to_base=to_base)

@app.route("/tools/trigonometry-calculator", methods=["GET", "POST"])
def trigonometry_calculator():
    result = None
    angle = ""
    func = "sin"
    deg = True
    if request.method == "POST":
        angle = request.form.get("angle", "")
        func = request.form.get("func", "sin")
        deg = request.form.get("deg") == "on"
        try:
            angle_unit = request.form.get("angle_unit", "deg")
            val = float(angle)
            if angle_unit == "deg":
                import math
                val = math.radians(val)
            elif angle_unit == "grad":
                val = val * (math.pi / 200)
            # else: radians, no change
            # Map function names to sympy functions
            func_map = {
                "sin": sin, "sin^-1": asin, "sinh": sinh, "sinh^-1": asinh,
                "cos": cos, "cos^-1": acos, "cosh": cosh, "cosh^-1": acosh,
                "tan": tan, "tan^-1": atan, "tanh": tanh, "tanh^-1": atanh,
                "cot": cot, "cot^-1": acot, "coth": coth, "coth^-1": acoth,
                "sec": sec, "sec^-1": asec, "sech": sech, "sech^-1": asech,
                "csc": csc, "csc^-1": acsc, "csch": csch, "csch^-1": acsch,
            }
            if func in func_map:
                result = func_map[func](val)
            else:
                result = "Invalid function"
        except Exception as e:
            result = f"Error: {e}"
    return render_template("tools/trigonometry_calculator.html", result=result, angle=angle, func=func, deg=deg)

@app.route("/tools/fraction-calculator", methods=["GET", "POST"])
def fraction_calculator():
    from fractions import Fraction
    result = None
    a = ""
    b = ""
    op = "+"
    if request.method == "POST":
        a = request.form.get("a", "")
        b = request.form.get("b", "")
        op = request.form.get("op", "+")
        try:
            fa = Fraction(a)
            fb = Fraction(b)
            if op == "+":
                result = fa + fb
            elif op == "-":
                result = fa - fb
            elif op == "*":
                result = fa * fb
            elif op == "/":
                result = fa / fb
            else:
                result = "Invalid operation"
        except Exception as e:
            result = f"Error: {e}"
    return render_template("tools/fraction_calculator.html", result=result, a=a, b=b, op=op)

@app.route("/upload-avatar", methods=["POST"])
@login_required
def upload_avatar():
    user = User.query.get(session["user_id"])
    if request.method == "POST":
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename, ['image']):
                filename = secure_filename(file.filename)
                path = os.path.join('static/avatars', filename)
                file.save(path)
                user.avatar_url = url_for('static', filename=f'avatars/{filename}')
                db.session.commit()
                flash("Avatar updated successfully!", "success")
            else:
                flash("Invalid file type. Please upload an image.", "danger")
    return redirect("/profile")

@app.route("/activity-log")
@login_required
def activity_log():
    logs = ActivityLog.query.filter_by(user_id=session["user_id"]).order_by(ActivityLog.timestamp.desc()).all()
    return render_template("activity_log.html", logs=logs)

@app.route("/import/notes", methods=["POST"])
@login_required
def import_notes():
    file = request.files.get("file")
    if file:
        reader = csv.DictReader(io.StringIO(file.read().decode()))
        for row in reader:
            note = Note(user_id=session["user_id"], content=row["content"])
            db.session.add(note)
        db.session.commit()
        flash("Notes imported!", "success")
    return redirect("/tools/notes")

@app.route("/import/todos", methods=["POST"])
@login_required
def import_todos():
    file = request.files.get("file")
    if file:
        reader = csv.DictReader(io.StringIO(file.read().decode()))
        for row in reader:
            todo = Todo(
                user_id=session["user_id"],
                content=row["content"],
                due_date=row.get("due_date"),
                completed=row.get("completed") == "True"
            )
            db.session.add(todo)
        db.session.commit()
        flash("Todos imported!", "success")
    return redirect("/tools/todo")

@app.route("/tools/ai-gemini-prompt", methods=["GET", "POST"])
def ai_gemini_prompt():
    result = None
    prompt = ""
    if request.method == "POST":
        prompt = request.form.get("prompt", "").strip()
        if prompt:
            try:
                model = genai.GenerativeModel('gemini-pro')
                response = model.generate_content(prompt)
                result = response.text
            except Exception as e:
                result = f"Error: {e}"
    return render_template("tools/ai_gemini_prompt.html", prompt=prompt, result=result)

@app.route("/tools/ai-paraphraser", methods=["GET", "POST"])
def ai_paraphraser():
    paraphrased = None
    text = ""
    if request.method == "POST":
        text = request.form.get("text", "")
        if text:
            try:
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "Paraphrase the following text."},
                        {"role": "user", "content": text}
                    ],
                    max_tokens=256,
                    temperature=0.7,
                )
                paraphrased = response.choices[0].message.content
            except Exception as e:
                paraphrased = f"Error: {e}"
    return render_template("tools/ai_paraphraser.html", paraphrased=paraphrased, text=text)

@app.route("/tools/color-generator", methods=["GET", "POST"])
def color_generator():
    import random
    result = []
    count = int(request.form.get("count", 1))
    fmt = request.form.get("format", "hex")
    if request.method == "POST":
        for _ in range(count):
            r = random.randint(0, 255)
            g = random.randint(0, 255)
            b = random.randint(0, 255)
            if fmt == "hex":
                color = "#{:02X}{:02X}{:02X}".format(r, g, b)
            elif fmt == "rgb":
                color = f"rgb({r}, {g}, {b})"
            elif fmt == "hsl":
                import colorsys
                h, l, s = colorsys.rgb_to_hls(r/255, g/255, b/255)
                color = f"hsl({int(h*360)}, {int(s*100)}%, {int(l*100)}%)"
            else:
                color = "#{:02X}{:02X}{:02X}".format(r, g, b)
            result.append(color)
    return render_template("tools/color_generator.html", result=result, count=count, fmt=fmt)

@app.route("/tools/gradient-generator", methods=["GET", "POST"])
def gradient_generator():
    colors = request.form.getlist("color") or ["#ff0000", "#0000ff"]
    direction = request.form.get("direction", "to right")
    gradient_type = request.form.get("type", "linear")
    css = ""
    if request.method == "POST":
        if gradient_type == "linear":
            css = f"linear-gradient({direction}, {', '.join(colors)})"
        else:
            css = f"radial-gradient(circle, {', '.join(colors)})"
    return render_template("tools/gradient_generator.html", colors=colors, direction=direction, gradient_type=gradient_type, css=css)

@app.route("/tools/palette-generator", methods=["GET", "POST"])
def palette_generator():
    import random
    import colorsys
    mode = request.form.get("mode", "random")
    base = request.form.get("base", "#3498db")
    palette = []
    if request.method == "POST":
        def hex_to_rgb(h):
            h = h.lstrip("#")
            return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
        def rgb_to_hex(r, g, b):
            return "#{:02X}{:02X}{:02X}".format(r, g, b)
        r, g, b = hex_to_rgb(base)
        h, l, s = colorsys.rgb_to_hls(r/255, g/255, b/255)
        if mode == "monochrome":
            for i in range(5):
                ll = min(1, max(0, l + (i-2)*0.15))
                palette.append(rgb_to_hex(*[int(x*255) for x in colorsys.hls_to_rgb(h, ll, s)]))
        elif mode == "complementary":
            palette = [base, rgb_to_hex(*[int(x*255) for x in colorsys.hls_to_rgb((h+0.5)%1, l, s)])]
        elif mode == "analogous":
            for delta in (-0.08, -0.04, 0, 0.04, 0.08):
                palette.append(rgb_to_hex(*[int(x*255) for x in colorsys.hls_to_rgb((h+delta)%1, l, s)]))
        elif mode == "triadic":
            palette = [base]
            for delta in (1/3, 2/3):
                palette.append(rgb_to_hex(*[int(x*255) for x in colorsys.hls_to_rgb((h+delta)%1, l, s)]))
        elif mode == "tetradic":
            palette = [base]
            for delta in (0.25, 0.5, 0.75):
                palette.append(rgb_to_hex(*[int(x*255) for x in colorsys.hls_to_rgb((h+delta)%1, l, s)]))
        elif mode == "split-complementary":
            palette = [base]
            for delta in (0.42, 0.58):
                palette.append(rgb_to_hex(*[int(x*255) for x in colorsys.hls_to_rgb((h+delta)%1, l, s)]))
        elif mode == "random":
            for _ in range(5):
                palette.append("#{0:06x}".format(random.randint(0, 0xFFFFFF)).upper())
    return render_template("tools/palette_generator.html", palette=palette, mode=mode, base=base)

@app.route("/tools/white-noise")
def white_noise():
    return render_template("tools/white_noise.html", sounds=WHITE_NOISE_SOUNDS)

WHITE_NOISE_SOUNDS = [
    {"key": "white", "icon": "bi-soundwave", "name": _(u"White Noise"), "desc": _(u"Classic static"), "file": None},
    {"key": "pink", "icon": "bi-soundwave", "name": _(u"Pink Noise"), "desc": _(u"Balanced static"), "file": None},
    {"key": "brown", "icon": "bi-soundwave", "name": _(u"Brown Noise"), "desc": _(u"Deep static"), "file": None},
    {"key": "rain", "icon": "bi-cloud-drizzle", "name": _(u"Rain"), "desc": _(u"Gentle rain"), "file": "rain.mp3"},
    {"key": "forest", "icon": "bi-tree", "name": _(u"Forest"), "desc": _(u"Birds & trees"), "file": "forest.mp3"},
    {"key": "night", "icon": "bi-moon-stars", "name": _(u"Night"), "desc": _(u"Crickets & night air"), "file": "night.mp3"},
    {"key": "ocean", "icon": "bi-water", "name": _(u"Ocean"), "desc": _(u"Waves"), "file": "ocean.mp3"},
    {"key": "wind", "icon": "bi-wind", "name": _(u"Wind"), "desc": _(u"Soft wind"), "file": "wind.mp3"},
    {"key": "fire", "icon": "bi-fire", "name": _(u"Fire"), "desc": _(u"Campfire crackle"), "file": "fire.mp3"},
    {"key": "thunder", "icon": "bi-cloud-lightning-rain", "name": _(u"Thunderstorm"), "desc": _(u"Rain & thunder"), "file": "thunder.mp3"},
    {"key": "cafe", "icon": "bi-cup-hot", "name": _(u"Cafe"), "desc": _(u"Coffee shop"), "file": "cafe.mp3"},
    {"key": "train", "icon": "bi-train-front", "name": _(u"Train"), "desc": _(u"Train ride"), "file": "train.mp3"},
    {"key": "fan", "icon": "bi-fan", "name": _(u"Fan"), "desc": _(u"Electric fan"), "file": "fan.mp3"},
    {"key": "fireplace", "icon": "bi-fire", "name": _(u"Fireplace"), "desc": _(u"Indoor fire"), "file": "fireplace.mp3"},
    {"key": "river", "icon": "bi-droplet", "name": _(u"River"), "desc": _(u"Flowing water"), "file": "river.mp3"},
    {"key": "birds", "icon": "bi-egg-fried", "name": _(u"Birds"), "desc": _(u"Morning birds"), "file": "birds.mp3"},
    {"key": "city", "icon": "bi-buildings", "name": _(u"City"), "desc": _(u"Urban ambience"), "file": "city.mp3"},
    {"key": "library", "icon": "bi-journal-bookmark", "name": _(u"Library"), "desc": _(u"Quiet study"), "file": "library.mp3"},
    {"key": "rainroof", "icon": "bi-house", "name": _(u"Rain on Roof"), "desc": _(u"Rain hitting roof"), "file": "rainroof.mp3"},
    {"key": "waves", "icon": "bi-water", "name": _(u"Waves"), "desc": _(u"Sea shore"), "file": "waves.mp3"},
    {"key": "fireplace2", "icon": "bi-fire", "name": _(u"Fireplace 2"), "desc": _(u"Cozy fire"), "file": "fireplace2.mp3"},
    {"key": "leaves", "icon": "bi-leaf", "name": _(u"Leaves"), "desc": _(u"Rustling leaves"), "file": "leaves.mp3"},
    {"key": "stream", "icon": "bi-droplet-half", "name": _(u"Stream"), "desc": _(u"Small creek"), "file": "stream.mp3"},
    {"key": "waterfall", "icon": "bi-droplet-fill", "name": _(u"Waterfall"), "desc": _(u"Falling water"), "file": "waterfall.mp3"},
    {"key": "crowd", "icon": "bi-people", "name": _(u"Crowd"), "desc": _(u"People talking"), "file": "crowd.mp3"},
    {"key": "market", "icon": "bi-shop", "name": _(u"Market"), "desc": _(u"Busy market"), "file": "market.mp3"},
    {"key": "jungle", "icon": "bi-flower2", "name": _(u"Jungle"), "desc": _(u"Tropical forest"), "file": "jungle.mp3"},
    {"key": "highway", "icon": "bi-truck", "name": _(u"Highway"), "desc": _(u"Cars passing"), "file": "highway.mp3"},
    {"key": "subway", "icon": "bi-train-lightrail-front", "name": _(u"Subway"), "desc": _(u"Underground train"), "file": "subway.mp3"},
    {"key": "trainstation", "icon": "bi-train-freight-front", "name": _(u"Train Station"), "desc": _(u"Station ambience"), "file": "trainstation.mp3"},
    {"key": "fountain", "icon": "bi-droplet", "name": _(u"Fountain"), "desc": _(u"Water fountain"), "file": "fountain.mp3"},
    {"key": "windchimes", "icon": "bi-wind", "name": _(u"Wind Chimes"), "desc": _(u"Chimes in wind"), "file": "windchimes.mp3"},
    {"key": "birdsforest", "icon": "bi-egg-fried", "name": _(u"Birds Forest"), "desc": _(u"Forest birds"), "file": "birdsforest.mp3"},
    {"key": "night2", "icon": "bi-moon-stars", "name": _(u"Night 2"), "desc": _(u"Night ambience"), "file": "night2.mp3"},
    {"key": "snow", "icon": "bi-snow", "name": _(u"Snow"), "desc": _(u"Falling snow"), "file": "snow.mp3"},
    {"key": "typing", "icon": "bi-keyboard", "name": _(u"Typing"), "desc": _(u"Keyboard typing"), "file": "typing.mp3"},
    {"key": "clock", "icon": "bi-clock", "name": _(u"Clock"), "desc": _(u"Ticking clock"), "file": "clock.mp3"},
    {"key": "laundry", "icon": "bi-droplet", "name": _(u"Laundry"), "desc": _(u"Washing machine"), "file": "laundry.mp3"},
    {"key": "vacuum", "icon": "bi-wind", "name": _(u"Vacuum"), "desc": _(u"Vacuum cleaner"), "file": "vacuum.mp3"},
    {"key": "hairdryer", "icon": "bi-wind", "name": _(u"Hair Dryer"), "desc": _(u"Blowing air"), "file": "hairdryer.mp3"},
    {"key": "car", "icon": "bi-car-front", "name": _(u"Car Ride"), "desc": _(u"Inside a car"), "file": "car.mp3"},
    {"key": "plane", "icon": "bi-airplane", "name": _(u"Airplane"), "desc": _(u"In-flight hum"), "file": "plane.mp3"},
    {"key": "boat", "icon": "bi-water", "name": _(u"Boat"), "desc": _(u"On a boat"), "file": "boat.mp3"},
    {"key": "heartbeat", "icon": "bi-heart-pulse", "name": _(u"Heartbeat"), "desc": _(u"Heartbeat sound"), "file": "heartbeat.mp3"},
    {"key": "catpurr", "icon": "bi-emoji-smile", "name": _(u"Cat Purr"), "desc": _(u"Purring cat"), "file": "catpurr.mp3"},
    {"key": "dogbark", "icon": "bi-emoji-smile", "name": _(u"Dog Bark"), "desc": _(u"Dog barking"), "file": "dogbark.mp3"},
    {"key": "frog", "icon": "bi-droplet", "name": _(u"Frogs"), "desc": _(u"Frogs croaking"), "file": "frog.mp3"},
    {"key": "crickets", "icon": "bi-moon-stars", "name": _(u"Crickets"), "desc": _(u"Night crickets"), "file": "crickets.mp3"},
    {"key": "beach", "icon": "bi-water", "name": _(u"Beach"), "desc": _(u"Beach waves"), "file": "beach.mp3"},
    {"key": "campfire", "icon": "bi-fire", "name": _(u"Campfire"), "desc": _(u"Outdoor fire"), "file": "campfire.mp3"},
    {"key": "rainforest", "icon": "bi-tree", "name": _(u"Rainforest"), "desc": _(u"Rainforest ambience"), "file": "rainforest.mp3"},
    {"key": "windy", "icon": "bi-wind", "name": _(u"Windy"), "desc": _(u"Strong wind"), "file": "windy.mp3"},
    {"key": "seagulls", "icon": "bi-egg-fried", "name": _(u"Seagulls"), "desc": _(u"Seagulls at sea"), "file": "seagulls.mp3"},
    {"key": "barn", "icon": "bi-house", "name": _(u"Barn"), "desc": _(u"Barn animals"), "file": "barn.mp3"},
    {"key": "trainwhistle", "icon": "bi-train-front", "name": _(u"Train Whistle"), "desc": _(u"Train horn"), "file": "trainwhistle.mp3"},
    {"key": "churchbells", "icon": "bi-bell", "name": _(u"Church Bells"), "desc": _(u"Bells ringing"), "file": "churchbells.mp3"},
    {"key": "windmill", "icon": "bi-wind", "name": _(u"Windmill"), "desc": _(u"Windmill blades"), "file": "windmill.mp3"},
    {"key": "rainwindow", "icon": "bi-shop-window", "name": _(u"Rain on Window"), "desc": _(u"Rain hitting glass"), "file": "rainwindow.mp3"},
    # Add more as you add files to static/media/ ...
]

@app.route("/tools/flashcards", methods=["GET", "POST"])
def flashcards():
    try:
        # Initialize session storage for flashcards if not present
        if "flashcard_sets" not in session:
            session["flashcard_sets"] = {"Default": []}
            session["flashcards_current_set"] = "Default"
            session.modified = True
        
        # Get all sets
        sets = list(session["flashcard_sets"].keys())
        if not sets:
            session["flashcard_sets"] = {"Default": []}
            sets = ["Default"]
            session.modified = True
    
        # Determine current set
        current_set = None
        
        # First try from form data
        if request.method == "POST":
            current_set = request.form.get("set")
        
        # Then try from session
        if not current_set:
            current_set = session.get("flashcards_current_set")
        
        # Finally default to "Default"
        if not current_set or current_set not in sets:
            current_set = "Default"
        
        # Ensure the current set exists in session
        if current_set not in session["flashcard_sets"]:
            # Make a copy of the current flashcard_sets
            flashcard_sets = dict(session["flashcard_sets"])
            flashcard_sets[current_set] = []
            session["flashcard_sets"] = flashcard_sets
            session.modified = True
        
        # Initialize variables
        error = None
        flashcards = session["flashcard_sets"][current_set].copy()  # Make a copy

        # Log current session state for debugging
        app.logger.info(f"Current flashcard set: {current_set}")
        app.logger.info(f"Sets: {sets}")
        app.logger.info(f"Current set cards: {len(flashcards)}")
        app.logger.info(f"Session size: {len(str(dict(session)))} bytes")

        if request.method == "POST":
            # Add new set
            if request.form.get("new_set"):
                new_set_name = request.form.get("new_set_name", "").strip()
                if new_set_name and new_set_name not in sets:
                    # Make a copy of the current flashcard_sets
                    flashcard_sets = dict(session["flashcard_sets"])
                    flashcard_sets[new_set_name] = []
                    session["flashcard_sets"] = flashcard_sets
                    session["flashcards_current_set"] = new_set_name
                    session.modified = True
                    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                        return jsonify({"success": True})
                    return redirect(url_for("flashcards"))
                else:
                    error = _("Set name must be unique and not empty.")
                    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                        return jsonify({"success": False, "error": error}), 400

            # Delete set
            elif request.form.get("delete_set"):
                set_to_delete = request.form.get("set", current_set)
                if set_to_delete in session["flashcard_sets"]:
                    if len(session["flashcard_sets"]) <= 1:
                        error = _("Cannot delete the last set.")
                        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                            return jsonify({"success": False, "error": error}), 400
                    else:
                        # Make a copy of the current flashcard_sets
                        flashcard_sets = dict(session["flashcard_sets"])
                        del flashcard_sets[set_to_delete]
                        
                        # If we're deleting the current set, switch to another one
                        if set_to_delete == current_set:
                            current_set = next(iter(flashcard_sets.keys()))
                            session["flashcards_current_set"] = current_set
                        
                        # Update session
                        session["flashcard_sets"] = flashcard_sets
                        session.modified = True
                        
                        app.logger.info(f"Deleted set {set_to_delete}, switched to {current_set}")
                        
                        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                            return jsonify({"success": True, "new_set": current_set})
                        return redirect(url_for("flashcards"))
                else:
                    error = _("Set not found.")
                    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                        return jsonify({"success": False, "error": error}), 404
            
            # Add card
            elif request.form.get("front") is not None and request.form.get("back") is not None:
                front = request.form.get("front", "").strip()
                back = request.form.get("back", "").strip()
                target_set = request.form.get("set", current_set)

                if not front or not back:
                    error = _("Both front and back are required.")
                    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                        return jsonify({"success": False, "error": error}), 400
                    return render_template("tools/flashcards.html", sets=sets, current_set=current_set, 
                                        flashcards=flashcards, error=error)

                # Make a copy of the current flashcard_sets
                flashcard_sets = dict(session["flashcard_sets"])
                
                # Initialize target set if it doesn't exist
                if target_set not in flashcard_sets:
                    flashcard_sets[target_set] = []
                
                # Add the new card to the set's cards
                target_cards = flashcard_sets[target_set].copy()
                target_cards.append({"front": front, "back": back})
                flashcard_sets[target_set] = target_cards
                
                # Update session
                session["flashcard_sets"] = flashcard_sets
                session["flashcards_current_set"] = target_set
                session.modified = True
                
                # Log the update
                app.logger.info(f"Added card to set {target_set}. Set now has {len(target_cards)} cards")
                
                # Check session size
                session_size = len(str(dict(session)))
                app.logger.info(f"Flashcard session size: {session_size} bytes")
                if session_size > 3500:
                    error = _("Too many flashcards! Please clear some cards or sets.")
                    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                        return jsonify({"success": False, "error": error}), 400
                    return render_template("tools/flashcards.html", sets=sets, current_set=current_set, 
                                        flashcards=flashcards, error=error)

                if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return jsonify({"success": True})
                return redirect(url_for("flashcards"))
            
            # Delete card
            elif request.form.get("delete_card") is not None:
                try:
                    idx = int(request.form.get("delete_card"))
                    delete_from_set = request.form.get("set", current_set)
                    
                    if delete_from_set in session["flashcard_sets"]:
                        current_cards = session["flashcard_sets"][delete_from_set].copy()
                        if 0 <= idx < len(current_cards):
                            # Remove the card
                            current_cards.pop(idx)
                            
                            # Update session
                            flashcard_sets = dict(session["flashcard_sets"])
                            flashcard_sets[delete_from_set] = current_cards
                            session["flashcard_sets"] = flashcard_sets
                            session.modified = True
                            
                            app.logger.info(f"Deleted card {idx} from set {delete_from_set}. Set now has {len(current_cards)} cards")
                            
                            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                                return jsonify({"success": True})
                            return redirect(url_for("flashcards"))
                        else:
                            error = _("Invalid card index.")
                            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                                return jsonify({"success": False, "error": error}), 400
                    else:
                        error = _("Invalid set.")
                        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                            return jsonify({"success": False, "error": error}), 400
                except (ValueError, TypeError):
                    error = _("Invalid card index.")
                    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                        return jsonify({"success": False, "error": error}), 400
            
            # Clear set
            elif request.form.get("clear_set"):
                if current_set in session["flashcard_sets"]:
                    # Make a copy of the current flashcard_sets
                    flashcard_sets = dict(session["flashcard_sets"])
                    flashcard_sets[current_set] = []
                    
                    # Update session
                    session["flashcard_sets"] = flashcard_sets
                    session.modified = True
                    
                    app.logger.info(f"Cleared set {current_set}")
                    
                    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                        return jsonify({"success": True})
                    return redirect(url_for("flashcards"))
                else:
                    error = _("Set not found.")
                    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                        return jsonify({"success": False, "error": error}), 404
                    flash(error, "danger")
                    return redirect(url_for("flashcards"))

            # Delete set
            elif request.form.get("delete_set"):
                set_to_delete = request.form.get("set", current_set)
                if set_to_delete in session["flashcard_sets"]:
                    if len(session["flashcard_sets"]) <= 1:
                        error = _("Cannot delete the last set.")
                        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                            return jsonify({"success": False, "error": error}), 400
                        flash(error, "danger")
                        return redirect(url_for("flashcards"))
                    
                    # Make a copy of the current flashcard_sets
                    flashcard_sets = dict(session["flashcard_sets"])
                    # Delete the set
                    del flashcard_sets[set_to_delete]
                    
                    # Update session
                    session["flashcard_sets"] = flashcard_sets
                    # If we deleted the current set, switch to the first available set
                    if set_to_delete == session.get("flashcards_current_set"):
                        session["flashcards_current_set"] = next(iter(flashcard_sets))
                    session.modified = True
                    
                    app.logger.info(f"Deleted set {set_to_delete}")
                    
                    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                        return jsonify({"success": True})
                    return redirect(url_for("flashcards"))
                else:
                    error = _("Set not found.")
                    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                        return jsonify({"success": False, "error": error}), 404
                    flash(error, "danger")
                    return redirect(url_for("flashcards"))
        return render_template(
            "tools/flashcards.html",
            sets=sets,
            current_set=current_set,
            flashcards=flashcards,
            error=error
        )
        
    except Exception as e:
        app.logger.error(f"Error in flashcards: {str(e)}")
        error = _("An error occurred. Please try again.")
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": error}), 500
        return render_template(
            "tools/flashcards.html",
            sets=sets or ["Default"],
            current_set=current_set or "Default",
            flashcards=[],
            error=error
        )

@app.route("/tools/star-map", methods=["GET", "POST"])
def star_map():
    from datetime import datetime
    lat = request.form.get("lat") or request.args.get("lat") or "0"
    lon = request.form.get("lon") or request.args.get("lon") or "0"
    date = request.form.get("date") or request.args.get("date") or datetime.now().strftime("%Y-%m-%d")
    time = request.form.get("time") or request.args.get("time") or datetime.now().strftime("%H:%M")
    return render_template("tools/star_map.html", lat=lat, lon=lon, date=date, time=time)

@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        email = request.form.get("email")
        rating = request.form.get("rating")
        message = request.form.get("message")
        category = request.form.get("category")
        code = request.form.get("code")
        
        # Basic validation
        if not email or not rating or not message:
            flash("All required fields must be filled out.", "danger")
            return render_template("feedback.html")
        
        # File handling
        screenshot = request.files.get("screenshot")
        screenshot_url = None
        
        if screenshot and allowed_file(screenshot.filename, ["images"]):
            filename = secure_filename(screenshot.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'feedback', filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            screenshot.save(filepath)
            screenshot_url = url_for('static', filename=f'uploads/feedback/{filename}')
        
        # Create feedback entry
        feedback = Feedback(
            user_id=session.get("user_id"),
            email=email,
            rating=int(rating),
            message=message,
            category=category,
            screenshot_url=screenshot_url,
            code=code
        )
        
        db.session.add(feedback)
        db.session.commit()
        
        # Log activity if user is logged in
        if session.get("user_id"):
            log_activity(session["user_id"], "submitted_feedback", f"Rating: {rating}")
        
        flash("Thank you for your feedback!", "success")
        return redirect(url_for("feedback"))
        
    return render_template("feedback.html")

@app.route("/tools/reverse-image-search", methods=["GET", "POST"]) 
def reverse_image_search():
    search_links = []
    filename = None
    image_url = None

    if request.method == "POST":
        image = request.files.get("image")

        if image and image.filename != "" and allowed_file(image.filename, ALLOWED_EXTENSIONS):
            filename = secure_filename(image.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'reverse_image_search', filename)

            # Ensure the directory exists
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            image.save(filepath)

            image_url = url_for('static', filename=f"uploads/reverse_image_search/{filename}", _external=True)

            flash("Image uploaded successfully!", "success")

            # Create reverse search URLs
            for engine in REVERSE_IMAGE_ENGINES:
                if engine["upload"]:
                    url = engine["url"]
                else:
                    url = f"{engine['url']}{image_url}"
                search_links.append({
                    "name": engine["name"],
                    "url": url,
                    "icon": engine.get("icon", "bi-search")
                })

        else:
            flash("Please upload a valid image file.", "danger")

    return render_template("tools/reverse_image_search.html", search_links=search_links, filename=filename, image_url=image_url)


@app.route("/credit")
def credits():
    return render_template("credit.html")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))