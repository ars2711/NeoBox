from dotenv import load_dotenv
load_dotenv()

import os
import requests
from functools import wraps
from flask import Flask, flash, redirect, render_template, request, session, get_flashed_messages, url_for, abort, g, jsonify
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
from werkzeug.security import check_password_hash, generate_password_hash
from flask_babel import Babel, gettext as _
from datetime import datetime, timezone
from flask_dance.contrib.google import make_google_blueprint, google
from flask_mail import Mail, Message
import random
from datetime import timedelta
import uuid
from werkzeug.utils import secure_filename
from PIL import Image
import PyPDF2
from googletrans import Translator, LANGUAGES
import zipfile
import io
from flask import send_file
import base64
from sqlalchemy.dialects.sqlite import JSON
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, AttestationObject, AuthenticatorData
from fido2 import cbor
from markupsafe import Markup

BIGDATACLOUD_API_KEY = os.environ.get("BIGDATACLOUD_API_KEY")

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function

db = SQLAlchemy()

# --- Update User Model to add otp and otp_expiry fields ---
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
    google_id = db.Column(db.String(128), unique=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    language = db.Column(db.String(10), default='en')
    theme = db.Column(db.String(10), default='auto')
    reset_token = db.Column(db.String(100), nullable=True)
    verified = db.Column(db.Boolean, default=False)
    verify_token = db.Column(db.String(100), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(10), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    passkeys = db.Column(JSON, default=list)  # Store list of passkey credentials

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))
Session(app)

db_name = os.path.join(os.path.dirname(__file__), 'users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_name
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'
babel = Babel(app)

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

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get("MAIL_USERNAME") or "no-reply@neobox.com"
mail = Mail(app)

rp = PublicKeyCredentialRpEntity(id="localhost", name="CS50 FP Demo")
fido2_server = Fido2Server(rp)

@app.context_processor
def inject_globals():
    return {
        'now': datetime.now(timezone.utc),
        'available_languages': AVAILABLE_LANGUAGES
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

@app.route("/")
def index():
    if session.get("user_id"):
        # Example: show first 3 tools as frequent (replace with real logic)
        frequent_tools = TOOLS[:3]
        # Get notifications for user
        notifications = Notification.query.filter_by(user_id=session["user_id"]).order_by(Notification.created_at.desc()).all()
        # Pick a random quote/question
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
        return render_template("landing.html", visitor_count=count)

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
        otp = request.form.get("otp").strip()
        if not otp:
            flash("Please enter the OTP.", "danger")
            return render_template("verify_otp.html")
        if user.otp != otp or not user.otp_expiry or datetime.now(timezone.utc) > user.otp_expiry:
            flash("Invalid or expired OTP.", "danger")
            return render_template("verify_otp.html")
        user.verified = True
        user.otp = None
        user.otp_expiry = None
        db.session.commit()
        session.pop("pending_user_id", None)
        flash("Your account has been verified! You can now log in.", "success")
        return redirect("/login")
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
        # Uniqueness check for phone
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
        session["theme"] = theme  # Optional: for instant theme switching
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
    {"name": "Calculator", "icon": "bi-calculator", "url": "calculator", "login_required": False, "description": "Simple arithmetic calculator."},
    {"name": "Scientific Calculator", "icon": "bi-calculator", "url": "scientific-calculator", "login_required": False, "description": "Advanced calculator for scientific functions."},
    {"name": "Unit Converter", "icon": "bi-arrow-left-right", "url": "unit-converter", "login_required": False, "description": "Convert between various units of measurement."},
    {"name": "Currency Converter", "icon": "bi-currency-exchange", "url": "currency-converter", "login_required": False, "description": "Convert currencies using real-time rates."},
    {"name": "To-do List", "icon": "bi-list-check", "url": "todo", "login_required": True, "description": "Manage your personal tasks and to-dos."},
    {"name": "File Converter", "icon": "bi-file-earmark-arrow-down", "url": "file-converter", "login_required": False, "description": "Convert files between different formats."},
    {"name": "Text Translator", "icon": "bi-translate", "url": "translator", "login_required": False, "description": "Translate text between languages."},
    {"name": "Search Engine Prompt", "icon": "bi-search", "url": "search", "login_required": False, "description": "Quickly search using your favorite search engines."},
    {"name": "Notes", "icon": "bi-journal-text", "url": "notes", "login_required": True, "description": "Write and save personal notes."},
    {"name": "Pomodoro Timer", "icon": "bi-hourglass-split", "url": "pomodoro", "login_required": False, "description": "Boost productivity with Pomodoro sessions."},
    {"name": "World Clocks", "icon": "bi-clock", "url": "world-clock", "login_required": False, "description": "View current times in cities worldwide."},
    {"name": "Timer", "icon": "bi-stopwatch", "url": "timer", "login_required": False, "description": "Set a countdown timer for any task."},
    {"name": "Stopwatch", "icon": "bi-stopwatch-fill", "url": "stopwatch", "login_required": False, "description": "Track elapsed time with a stopwatch."},
    {"name": "AI Prompt", "icon": "bi-robot", "url": "ai-prompt", "login_required": False, "description": "Get instant responses from a demo AI."},
    {"name": "Reverse Image Search", "icon": "bi-image", "url": "reverse-image-search", "login_required": False, "description": "Find similar images on the web."},
    {"name": "URL Shortener", "icon": "bi-link-45deg", "url": "url-shortener", "login_required": False, "description": "Shorten long URLs for easy sharing."},
    {"name": "Interactive Periodic Table", "icon": "bi-tablet", "url": "periodic-table", "login_required": False, "description": "Explore elements and their properties."},
    {"name": "Image Metadata Viewer", "icon": "bi-info-circle", "url": "image-metadata", "login_required": False, "description": "View metadata of uploaded images."},
    {"name": "Custom URL Redirects", "icon": "bi-arrow-right-circle", "url": "url-redirects", "login_required": False, "description": "Create custom redirects for your URLs."},

    # Current tools
]

UPCOMING_TOOLS = [
    
      {"name": "File Renamer", "icon": "bi-file-earmark-font", "soon": "Renaming soon"},
      {"name": "Text Encryptor/Decryptor", "icon": "bi-shield-lock", "soon": "Encrypting soon"},
      {"name": "Image Enlarger", "icon": "bi-arrows-angle-expand", "soon": "Enlarging soon"},
      {"name": "Daily Routines/Reminders", "icon": "bi-calendar-check", "soon": "Reminding soon"},
      {"name": "Maps", "icon": "bi-geo-alt", "soon": "Mapping soon"},
      {"name": "Color Generator", "icon": "bi-palette", "soon": "Coloring soon"},
      {"name": "Gradient Generator", "icon": "bi-palette2", "soon": "Blending soon"},
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
      {"name": "Flashcards/Study Tools", "icon": "bi-card-list", "soon": "Studying soon"},
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
      {"name": "AI Chatbot", "icon": "bi-chat-dots", "soon": "Chatting soon"},
      {"name": "Collaborative Documents", "icon": "bi-file-earmark-text", "soon": "Collaborating soon"},
      {"name": "Event Planner", "icon": "bi-calendar-event", "soon": "Planning soon"},
      {"name": "Game Zone", "icon": "bi-controller", "soon": "Gaming soon"},
      {"name": "Astrology/Star Map", "icon": "bi-stars", "soon": "Stargazing soon"},
      {"name": "Regex Tester", "icon": "bi-slash-square", "soon": "Testing soon"},
      {"name": "Image Cropper", "icon": "bi-crop", "soon": "Cropping soon"},
      {"name": "ASCII Art Generator", "icon": "bi-type", "soon": "ASCII soon"},
      {"name": "BPM Calculator", "icon": "bi-music-note-list", "soon": "Tapping soon"},
      {"name": "Color Palette Generator", "icon": "bi-palette-fill", "soon": "Paletting soon"},
      {"name": "White Noise Generator", "icon": "bi-volume-mute", "soon": "Soothing soon"},
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
    # ... more upcoming tools ...
]

ALLOWED_EXTENSIONS = {
    "image": {"png", "jpg", "jpeg", "bmp", "gif", "webp"},
    "pdf": {"pdf"},
    "text": {"txt", "md", "csv"},
    "doc": {"docx", "doc"},
    # Add more as needed
}

def allowed_file(filename, types):
    ext = filename.rsplit('.', 1)[-1].lower()
    return any(ext in ALLOWED_EXTENSIONS[t] for t in types)

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
            # No factors, handled specially
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
                # Special handling for temperature
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

@app.route("/tools/currency-converter", methods=["GET", "POST"])
def currency_converter():
    try:
        resp = requests.get("https://www.frankfurter.app/currencies")
        currencies = sorted(resp.json().items())
    except Exception:
        currencies = [("USD", "US Dollar"), ("EUR", "Euro"), ("GBP", "British Pound")]

    result = None
    amount = None
    from_currency = None
    to_currency = None

    if request.method == "POST":
        amount = request.form.get("amount")
        from_currency = request.form.get("from_currency")
        to_currency = request.form.get("to_currency")
        try:
            amount = float(amount)
            url = f"https://www.frankfurter.app/latest?amount={amount}&from={from_currency}&to={to_currency}"
            resp = requests.get(url)
            data = resp.json()
            result = data["rates"][to_currency]
        except Exception as e:
            result = f"Error: {e}"

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

@app.route("/notes")
@login_required
def notes():
    return render_template("notes.html")

@app.route("/tools")
def tools():
    logged_in = bool(session.get("user_id"))
    query = request.args.get("q", "").strip().lower()
    filtered_tools = TOOLS
    if query:
        filtered_tools = [tool for tool in TOOLS if query in tool["name"].lower()]
    return render_template("tools.html", tools=filtered_tools, upcoming_tools=UPCOMING_TOOLS, logged_in=logged_in, query=query)

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

def get_locale():
    return session.get("lang", "en")

babel = Babel(app, locale_selector=get_locale)

@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        email = request.form.get("email")
        rating = request.form.get("rating")
        message = request.form.get("message")
        user_id = session.get("user_id")
        if not message or not rating:
            flash("Please provide a rating and feedback message.", "danger")
            return redirect("/feedback")
        fb = Feedback(user_id=user_id, email=email, rating=int(rating), message=message)
        db.session.add(fb)
        db.session.commit()
        flash("Thank you for your feedback!", "success")
        return redirect("/")
    return render_template("feedback.html")

@app.route("/tools/todo", methods=["GET", "POST"])
@login_required
def todo():
    if "todos" not in session:
        session["todos"] = []
    if request.method == "POST":
        task = request.form.get("task")
        if task:
            session["todos"].append(task)
            session.modified = True
    return render_template("tools/todo.html", todos=session["todos"])

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
        # Add more as needed for your use case!
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



@app.route("/tools/translator", methods=["GET", "POST"])
def translator():
    result = ""
    text = ""
    src = "en"
    dest = "es"
    languages = list(LANGUAGES.items())
    # Add some easter egg languages
    languages += [("xx-bork", "Bork Bork Bork!"), ("xx-pirate", "Pirate"), ("xx-hacker", "Hacker Speak")]
    if request.method == "POST":
        text = request.form.get("text", "")
        src = request.form.get("src", "en")
        dest = request.form.get("dest", "es")
        if src == dest:
            result = "Input and output languages cannot be the same."
        elif dest == "xx-bork":
            # Swedish Chef Borkify
            result = text.replace("the", "zee").replace("a", "e").replace("o", "oo") + " Bork Bork Bork!"
        elif dest == "xx-pirate":
            # Pirate-ify
            result = text.replace("my", "me").replace("you", "ye").replace("is", "be").replace("friend", "matey") + " Arrr!"
        elif dest == "xx-hacker":
            # Hacker speak (leet)
            result = text.translate(str.maketrans("aeios", "43105"))
        else:
            try:
                translator = Translator()
                translated = translator.translate(text, src=src, dest=dest)
                result = translated.text
            except Exception as e:
                result = f"Error: {e}"
    return render_template(
        "tools/translator.html",
        result=result,
        text=text,
        src=src,
        dest=dest,
        languages=languages
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

@app.route("/tools/stopwatch")
def stopwatch():
    return render_template("tools/stopwatch.html")

@app.route("/tools/timer")
def timer():
    return render_template("tools/timer.html")

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
    metadata = None
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
                # Get metadata
                metadata = dict(img.info)
                # Try EXIF
                exif_data = img.getexif()
                if exif_data:
                    exif = {Image.ExifTags.TAGS.get(k, k): v for k, v in exif_data.items()}
                    metadata.update(exif)
                if not metadata:
                    metadata = {"Info": "No metadata found."}
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
        if not original or not custom:
            error = "Both fields are required."
        elif custom in short_urls:
            error = "Custom short URL already taken."
        else:
            short_urls[custom] = original
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
    """
    AI Prompt Tool: Accepts a prompt from the user and returns a response.
    For demo, uses a simple rule-based response. Replace with real API (e.g., OpenAI) as needed.
    """
    result = None
    prompt = ""
    if request.method == "POST":
        prompt = request.form.get("prompt", "").strip()
        if not prompt:
            result = "Please enter a prompt."
        else:
            # --- Demo logic: Replace this with a real AI API call if available ---
            if "hello" in prompt.lower():
                result = "Hello! How can I help you today?"
            elif "joke" in prompt.lower():
                result = "Why did the computer show up at work late? It had a hard drive!"
            else:
                result = f"I'm just a demo AI. You said: {prompt}"
    return render_template("tools/ai_prompt.html", prompt=prompt, result=result)

if __name__ == "__main__":
    app.run(debug=True)