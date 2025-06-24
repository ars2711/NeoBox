# === Load Environment Variables ===
from dotenv import load_dotenv
load_dotenv()

# === Standard Library ===
import os
import io
import csv
import zipfile
import uuid
import time
import base64
import random
import string
import requests
from datetime import datetime, timezone, timedelta
from functools import wraps
from urllib.parse import quote_plus

# === Flask Core ===
from flask import (
    Flask, flash, redirect, render_template, request, session, url_for,
    abort, g, jsonify, send_file, Response, after_this_request, get_flashed_messages
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_babel import Babel, gettext as _
from flask_dance.contrib.google import make_google_blueprint, google

# === Security & File Handling ===
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# === Image & PDF ===
from PIL import Image, ExifTags
import PyPDF2

# === AI & Translation ===
from openai import OpenAI
import google.generativeai as genai
from deep_translator import GoogleTranslator

# === WebAuthn (Passkeys) ===
from fido2 import cbor
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

# === Math & Symbolic Computation ===
from sympy import (
    symbols, sympify, integrate, diff, solve, Eq,
    sin, cos, tan, exp, log, Matrix, asin, acos, atan,
    acot, asec, acsc, sinh, cosh, tanh, coth, sech, csch,
    asinh, acosh, atanh, acoth, asech, acsch, cot, sec, csc, pi, E
)

# === SQLAlchemy Extras ===
from sqlalchemy.sql import text
from sqlalchemy.dialects.sqlite import JSON

# === HTML/Markup Utilities ===
from markupsafe import Markup

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

# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# --- Dict Lists ---
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
    {"name": "Voice-to-Text", "icon": "bi-mic", "url": "voice-to-text", "category": "conversion", "login_required": False, "description": "Convert speech to text with live and file upload options."},

    # Productivity
    {"name": "Pomodoro Timer", "icon": "bi-hourglass-split", "url": "pomodoro", "category": "productivity", "login_required": False, "description": "Boost productivity with Pomodoro sessions."},
    {"name": "Text Encryptor/Decryptor", "icon": "bi-shield-lock", "url": "text-encryptor", "category": "productivity", "login_required": False, "description": "Encrypt and decrypt text with custom keys and algorithms."},
    {"name": "Maps", "icon": "bi-geo-alt", "url": "maps", "category": "productivity", "login_required": False, "description": "Interactive maps with search, routes, filters, and saved spots."},
    {"name": "Daily Quotes", "icon": "bi-chat-quote", "url": "daily-quotes", "category": "productivity", "login_required": False, "description": "Get a new inspirational quote every day."},
    {"name": "Daily Questions", "icon": "bi-question-circle", "url": "daily-questions", "category": "productivity", "login_required": False, "description": "Get a new thought-provoking question every day."},
    {"name": "Flashcards", "icon": "bi-card-list", "url": "flashcards", "category": "productivity", "login_required": False, "description": "Create and study flashcards."},
    {"name": "Markdown Previewer", "icon": "bi-filetype-md", "url": "markdown-previewer", "category": "productivity", "login_required": False, "description": "Preview and render Markdown text live."},
    
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
    {"name": "Random Generator", "icon": "bi-shuffle", "url": "random-generator", "category": "other", "login_required": False, "description": "Generate random numbers, strings, colors, and more."},
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
    {"name": "File Renamer", "icon": "bi-file-earmark-font", "url": "file-renamer", "category": "files", "login_required": False, "description": "Rename files in bulk with patterns and rules."},
    {"name": "Image Enlarger", "icon": "bi-arrows-angle-expand", "url": "image-enlarger", "category": "files", "login_required": False, "description": "Resize, upscale, compress, and convert images in bulk."},
    {"name": "Daily Routines/Reminders", "icon": "bi-calendar-check", "url": "daily-routines", "category": "productivity", "login_required": True, "description": "Set daily routines and reminders with notifications."},
    {"name": "Password Manager", "icon": "bi-key", "url": "password-manager", "category": "security", "login_required": True, "description": "Securely store and manage your passwords."},
    {"name": "QR Code Tools", "icon": "bi-qr-code-scan", "url": "qr-code-tools", "category": "files", "login_required": False, "description": "Generate, customize, and read QR codes with advanced options."},
    {"name": "PDF Tools", "icon": "bi-file-earmark-pdf", "url": "pdf-tools", "category": "files", "login_required": False, "description": "Merge, split, compress, convert, and secure PDFs."},
    {"name": "Text-to-Speech", "icon": "bi-volume-up", "url": "text-to-speech", "category": "ai", "login_required": False, "description": "Convert text to speech in multiple languages and accents."},
    {"name": "Mind-maps/Flowcharts", "icon": "bi-diagram-3", "url": "mind-maps", "category": "productivity", "login_required": False, "description": "Create interactive mind maps and flowcharts."},
    {"name": "Code Formatter", "icon": "bi-code-slash", "url": "code-formatter", "category": "productivity", "login_required": False, "description": "Format and beautify code in multiple languages."},
    {"name": "Expense Tracker", "icon": "bi-cash-stack", "url": "expense-tracker", "category": "productivity", "login_required": True, "description": "Track your expenses and spending habits."},
    {"name": "Budget Tracker", "icon": "bi-wallet2", "url": "budget-tracker", "category": "productivity", "login_required": True, "description": "Plan and monitor your monthly budgets."},
    {"name": "Habit Tracker", "icon": "bi-check2-circle", "url": "habit-tracker", "category": "productivity", "login_required": True, "description": "Build and track habits with reminders."},
    {"name": "Grocery List Manager", "icon": "bi-basket", "url": "grocery-list", "category": "productivity", "login_required": True, "description": "Manage your grocery shopping lists."},
    {"name": "Health Tracker", "icon": "bi-heart-pulse", "url": "health-tracker", "category": "productivity", "login_required": True, "description": "Track your health data and progress."},
    {"name": "Collaborative Notes", "icon": "bi-people", "url": "collaborative-notes", "category": "productivity", "login_required": True, "description": "Create and share notes collaboratively."},
    {"name": "Basic Drawing", "icon": "bi-brush", "url": "basic-drawing", "category": "productivity", "login_required": False, "description": "Draw and sketch on a simple canvas."},
    {"name": "Stock/Market Tracker", "icon": "bi-graph-up", "url": "stock-market-tracker", "category": "productivity", "login_required": True, "description": "Track stocks and market data."},
    {"name": "Bookmark Manager", "icon": "bi-bookmark-star", "url": "bookmark-manager", "category": "productivity", "login_required": True, "description": "Save and organize your bookmarks."},
    {"name": "Text Case Converter", "icon": "bi-textarea-resize", "url": "text-case-convertor", "category": "productivity", "login_required": False, "description": "Convert text between different cases and styles."},
    {"name": "Password Generator", "icon": "bi-key", "url": "password-generator", "category": "security", "login_required": False, "description": "Generate strong, customizable passwords."},
]
UPCOMING_TOOLS = [
    {"name": "Custom Calendar", "icon": "bi-calendar-range", "soon": "Planning soon"},
    {"name": "Weather", "icon": "bi-cloud-sun", "soon": "Forecasting soon"},
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
    # TODO: Add more upcoming tools
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
    #TODO: Add more reverse image search engines
]
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
    # TODO: Add more white nosie files or sounds
]
DAILY_QUOTES = [
    "Stay positive, work hard, make it happen.",
    "Success is not for the lazy.",
    "Dream big and dare to fail.",
    #TODO: Add more daily quotes
]
DAILY_QUESTIONS = [
    "What is one thing you want to accomplish today?",
    "What are you grateful for today?",
    "How will you challenge yourself today?",
    #TODO: Add more daily questions
]

# === Routes ===
# --- Index Route ---
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

# --- Manifest JSON Route ---
@app.route("/manifest.json")
def manifest():
    return send_file("static/manifest.json")

# -- Terms and Conditions Route ---
@app.route("/terms")
def terms():
    return render_template("terms.html")

# -- Privacy Policy Route ---
@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

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
            return redirect(url_for("register"))
        if password != confirmation:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))
        if User.query.filter((User.username == username) | (User.email == email) | (User.phone == phone)).first():
            flash("Username, email, or phone already exists.", "danger")
            return redirect(url_for("register"))
        # Convert dob string to date object
        dob_obj = None
        if dob:
            try:
                dob_obj = datetime.strptime(dob, "%Y-%m-%d").date()
            except Exception:
                flash("Invalid date of birth format.", "danger")
                return redirect(url_for("register"))
        # Create user (unverified)
        hash_pw = generate_password_hash(password)
        otp = generate_otp()
        otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
        user = User(
            username=username,
            email=email,
            phone=phone,
            dob=dob_obj,
            gender=gender,
            hash=hash_pw,
            verified=False,
            otp=otp,
            otp_expiry=otp_expiry
        )
        db.session.add(user)
        db.session.commit()
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
            return render_template("verify_otp", email=user.email)

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
            return redirect(url_for("login"))
        if not user.verified:
            session["pending_user_id"] = user.id
            flash("Account not verified. Please check your email for the OTP.", "warning")
            return render_template("verify_otp")
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
            return redirect(url_for("forgot"))
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
            return render_template("verify_otp")
        if user.otp != otp or not user.otp_expiry or datetime.now(timezone.utc) > user.otp_expiry:
            flash("Invalid or expired OTP.", "danger")
            return render_template("verify_otp")
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
            return redirect(url_for("reset", token=token))
        if password != confirmation:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("reset", token=token))
        user.hash = generate_password_hash(password)
        user.reset_token = None
        db.session.commit()
        session.pop("reset_user_id", None)
        session.pop("reset_token", None)
        flash("Password reset successful! You can now log in.", "success")
        return redirect("/login")
    return render_template("reset.html", token=token)

# --- Verify Email Route ---
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

# --- Logout Route ---
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect("/login")

# --- Change Password Route ---
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

# --- Profile Page Route ---
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

# --- Avatar Upload Route ---
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

# --- Delete Account Route ---
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

# --- Google OAuth Login Route ---
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

# --- Notifications Route ---
@app.route("/notifications")
@login_required
def notifications():
    notes = Notification.query.filter_by(user_id=session["user_id"]).order_by(Notification.created_at.desc()).all()
    return render_template("notifications.html", notes=notes)

# --- Activity Log Route ---
@app.route("/activity-log")
@login_required
def activity_log():
    logs = ActivityLog.query.filter_by(user_id=session["user_id"]).order_by(ActivityLog.timestamp.desc()).all()
    return render_template("activity_log.html", logs=logs)

# --- Admin Routes ---
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

# --- Settings Route ---
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

# --- Passkey Registration and Login Routes ---
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

# --- Language Setting Route ---
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

# --- Feedback (tool) Routes ---
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

# --- Credits/Accreditations Route ---
@app.route("/credit")
def credits():
    return render_template("credit.html")

# --- Tools Page Route ---
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
        wip_tools=WIP_TOOLS,  # Always show WIP tools
        logged_in=logged_in,
        query=query,
        tool_categories=TOOL_CATEGORIES,
    )
    
# --- Unit Converter (tool) Route ---
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

# --- Currency Converter (tool) Route ---
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

# --- Basic Calculator (tool) Route ---
@app.route("/tools/calculator", methods=["GET", "POST"])
def calculator():
    result = None
    if request.method == "POST":
        try:
            a = request.form.get("a")
            b = request.form.get("b")
            op = request.form.get("op")
            if not a or not b or not op:
                flash("All fields are required.", "danger")
                return redirect(url_for("calculator"))
            a = float(a)
            b = float(b)
            if op == "+":
                result = a + b
            elif op == "-":
                result = a - b
            elif op == "*":
                result = a * b
            elif op == "/":
                if b == 0:
                    flash("Division by zero is not allowed.", "danger")
                    result = None
                else:
                    result = a / b
            else:
                flash("Invalid operation.", "danger")
                result = None
            if result is not None:
                flash("Calculation successful!", "success")
        except Exception as e:
            flash(f"Error: {e}", "danger")
    return render_template("tools/calculator.html", result=result)

# --- File Converter (tool) Route ---
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
        #TODO: Add more categories as needed
    }
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

# --- Image Metadata (tool) Route ---
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

# --- Integration Calculator (tool) Routes ---
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
    return render_template(
        "tools/integration_calculator.html",
        result=result,
        expr=expr,
        var=var,
        lower=lower,
        upper=upper
    )

# --- Differentiation Calculator (tool) Routes ---
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
    return render_template(
        "tools/differentiation_calculator.html",
        result=result,
        expr=expr,
        var=var
    )

# --- Equation Solver (tool) Routes ---
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
    return render_template(
        "tools/equation_solver.html",
        result=result,
        eqn=eqn,
        var=var
    )

# --- Matrix Calculator (tool) Routes ---
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

# --- Complex Number Calculator (tool) Routes ---
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
    return render_template(
        "tools/complex_calculator.html",
        result=result,
        a=a,
        b=b,
        op=op
    )

# --- Fraction Calculator (tool) Routes ---
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
    return render_template(
        "tools/fraction_calculator.html",
        result=result,
        a=a,
        b=b,
        op=op
    )

# --- Statistics Calculator (tool) Routes ---
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
    return render_template(
        "tools/statistics_calculator.html",
        result=result,
        data=data,
        stat=stat
    )

# --- Base Converter (tool) Routes ---
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
    return render_template(
        "tools/base_converter.html",
        result=result,
        number=number,
        from_base=from_base,
        to_base=to_base
    )

# --- Trigonometry Calculator (tool) Routes ---
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
    return render_template(
        "tools/trigonometry_calculator.html",
        result=result,
        angle=angle,
        func=func,
        deg=deg
    )

# --- AI Gemini Prompt (tool) Routes ---
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
    return redirect(url_for("ai_gemini_prompt", prompt=prompt, result=result))

# --- AI Text Paraphraser (tool) Routes ---
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
    return redirect(url_for("ai_paraphraser", paraphrased=paraphrased, text=text))

# --- Gradient Generator (tool) Routes ---
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
    return redirect(url_for("gradient_generator", colors=colors, direction=direction, gradient_type=gradient_type, css=css))

# --- Color Palette Generator (tool) Routes ---
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
    return redirect(url_for("palette_generator", palette=palette, mode=mode, base=base))

# --- White Noise Generator (tool) Route ---
@app.route("/tools/white-noise")
def white_noise():
    return render_template("tools/white_noise.html", sounds=WHITE_NOISE_SOUNDS)

# --- Flashcards (tool) Routes ---
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
                        # Delete the set
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
                    return redirect(url_for("flashcards", sets=sets, current_set=current_set, 
                                        flashcards=flashcards, error=error))

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
                    return redirect(url_for("flashcards", sets=sets, current_set=current_set, 
                                        flashcards=flashcards, error=error))

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
        return redirect(url_for(
            "flashcards",
            sets=sets,
            current_set=current_set,
            flashcards=flashcards,
            error=error
        ))
        
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

# --- Astrology/Star Map (tool) Routes ---
@app.route("/tools/star-map", methods=["GET", "POST"])
def star_map():
    from datetime import datetime
    lat = request.form.get("lat") or request.args.get("lat") or "0"
    lon = request.form.get("lon") or request.args.get("lon") or "0"
    date = request.form.get("date") or request.args.get("date") or datetime.now().strftime("%Y-%m-%d")
    time = request.form.get("time") or request.args.get("time") or datetime.now().strftime("%H:%M")
    return render_template("tools/star_map.html", lat=lat, lon=lon, date=date, time=time)

# --- Reverse Image Search (tool) Routes ---
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
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            image.save(filepath)
            image_url = url_for('static', filename=f"uploads/reverse_image_search/{filename}", _external=True)
            flash("Image uploaded successfully!", "success")
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

    return render_template(
        "tools/reverse_image_search.html",
        search_links=search_links,
        filename=filename,
        image_url=image_url
    )

# --- Scientific Calculator (tool) Route ---
@app.route("/tools/scientific-calculator")
def scientific_calculator():
    return render_template("tools/scientific_calculator.html")

# --- To-Do List (tool) Route ---
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
    return redirect(url_for("todo", todos=todos))

# --- Note-taking (tool) Route ---
@app.route("/tools/notes", methods=["GET", "POST"])
@login_required
def notes():
    if request.method == "POST":
        content = request.form.get("content")
        note = Note(user_id=session["user_id"], content=content)
        db.session.add(note)
        db.session.commit()
    notes = Note.query.filter_by(user_id=session["user_id"]).order_by(Note.created_at.desc()).all()
    return redirect(url_for("notes", notes=notes))

# --- Notes and To-Do Export Routes ---
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

# --- Notes and To-Do Import Routes ---
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

# --- File Renamer (tool) Route ---
@app.route("/tools/file-renamer", methods=["GET", "POST"])
def file_renamer():
    if request.method == "POST":
        files = request.files.getlist("files")
        new_name = request.form.get("new_name", "").strip()
        for file in files:
            if file and allowed_file(file.filename, ALLOWED_EXTENSIONS):
                original_filename = secure_filename(file.filename)
                file_ext = os.path.splitext(original_filename)[1]
                new_filename = new_name + file_ext
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
                flash(f"Renamed and uploaded: {new_filename}", "success")
            else:
                flash("Invalid file type. Please upload an image or document.", "danger")
    return render_template("tools/file_renamer.html")

# --- Text Encryptor/Decryptor (tool) Route ---
@app.route("/tools/text-encryptor", methods=["GET", "POST"])
def text_encryptor():
    from cryptography.fernet import Fernet
    key = os.environ.get("FERNET_KEY")
    if not key:
        key = Fernet.generate_key().decode()
    result = None
    text = ""
    action = "encrypt"
    user_key = ""
    if request.method == "POST":
        text = request.form.get("text", "")
        action = request.form.get("action", "encrypt")
        user_key = request.form.get("user_key", key)
        try:
            fernet = Fernet(user_key.encode())
            if action == "encrypt":
                result = fernet.encrypt(text.encode()).decode()
            elif action == "decrypt":
                result = fernet.decrypt(text.encode()).decode()
        except Exception as e:
            result = f"Error: {e}"
    return render_template(
        "tools/text_encryptor.html",
        result=result,
        text=text,
        action=action,
        user_key=user_key or key
    )

# --- Image Enlarger (tool) Route ---
@app.route("/tools/image-enlarger", methods=["GET", "POST"])
def image_enlarger():
    import base64, io
    from PIL import Image, ExifTags

    results = []
    if request.method == "POST":
        files = request.files.getlist("images")
        width = request.form.get("width")
        height = request.form.get("height")
        scale = float(request.form.get("scale", 100)) / 100
        fmt = request.form.get("format", "png")
        quality = int(request.form.get("quality", 90))
        dpi = int(request.form.get("dpi", 300))
        preserve_aspect = "preserve_aspect" in request.form
        strip_metadata = "strip_metadata" in request.form

        for file in files:
            if file and file.filename:
                img = Image.open(file)
                orig_size = img.size
                # Resize
                if width and height:
                    new_size = (int(width), int(height))
                else:
                    new_size = (int(img.width * scale), int(img.height * scale))
                if preserve_aspect:
                    img.thumbnail(new_size)
                else:
                    img = img.resize(new_size)
                # Strip metadata
                if strip_metadata:
                    img.info.pop("exif", None)
                # Save to buffer
                buf = io.BytesIO()
                save_kwargs = {"format": fmt.upper()}
                if fmt.lower() in ["jpg", "jpeg"]:
                    save_kwargs["quality"] = quality
                    save_kwargs["dpi"] = (dpi, dpi)
                img.save(buf, **save_kwargs)
                buf.seek(0)
                results.append({
                    "format": fmt,
                    "data": base64.b64encode(buf.read()).decode(),
                    "size": round(buf.tell() / 1024, 2)
                })
    return render_template("tools/image_enlarger.html", results=results, _=_)

# --- Daily Routines/Reminders (tool) Route ---
@app.route("/tools/daily-routines", methods=["GET", "POST"])
@login_required
def daily_routines():
    if request.method == "POST":
        title = request.form.get("title")
        time = request.form.get("time")
        frequency = request.form.get("frequency")
        routine = {
            "title": title,
            "time": time,
            "frequency": frequency
        }
        # Add to user's routines (JSON field)
        user = User.query.get(session["user_id"])
        routines = user.routines or []
        routines.append(routine)
        user.routines = routines
        db.session.commit()
        flash("Routine added!", "success")
        return redirect(url_for("daily_routines"))
    user = User.query.get(session["user_id"])
    routines = user.routines if user else []
    return render_template("tools/daily_routines.html", routines=routines)

# --- Maps (tool) Route ---
@app.route("/tools/maps")
def maps():
    return render_template("tools/maps.html")

# --- Password Manager (tool) Route ---
@app.route("/tools/password-manager", methods=["GET", "POST"])
@login_required
def password_manager():
    if request.method == "POST":
        site = request.form.get("site")
        username = request.form.get("username")
        password = request.form.get("password")
        # Save to user's password vault (JSON field)
        user = User.query.get(session["user_id"])
        vault = user.password_vault or {}
        vault[site] = {
            "username": username,
            "password": password
        }
        user.password_vault = vault
        db.session.commit()
        flash("Password saved!", "success")
        return redirect(url_for("password_manager"))
    user = User.query.get(session["user_id"])
    vault = user.password_vault if user else {}
    return render_template("tools/password_manager.html", vault=vault)

# --- QR Code Tools (tool) Route ---
@app.route("/tools/qr-code-tools", methods=["GET", "POST"])
def qr_code_tools():
    import qrcode
    import qrcode.image.svg
    import base64
    import io
    from PIL import Image, ImageDraw
    from pyzbar.pyzbar import decode as qr_decode

    img_data = None
    qr_result = None
    error = None

    if request.method == "POST":
        # QR Generation
        data = request.form.get("data", "")
        color = request.form.get("color", "#000000")
        bgcolor = request.form.get("bgcolor", "#ffffff")
        error_level = request.form.get("error", "M")
        logo_file = request.files.get("logo")
        shape = request.form.get("shape", "square")
        size = int(request.form.get("size", 10))
        fmt = request.form.get("format", "png")
        if data:
            try:
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=getattr(qrcode.constants, f"ERROR_CORRECT_{error_level}"),
                    box_size=size,
                    border=4,
                )
                qr.add_data(data)
                qr.make(fit=True)
                if fmt == "svg":
                    img = qr.make_image(image_factory=qrcode.image.svg.SvgImage, fill_color=color, back_color=bgcolor)
                    buf = io.BytesIO()
                    img.save(buf)
                    img_data = base64.b64encode(buf.getvalue()).decode()
                else:
                    img = qr.make_image(fill_color=color, back_color=bgcolor).convert("RGBA")
                    # Add logo if provided
                    if logo_file and logo_file.filename:
                        logo = Image.open(logo_file).convert("RGBA")
                        # Resize logo
                        box = (img.size[0] // 4, img.size[1] // 4)
                        logo.thumbnail(box)
                        # Center logo
                        pos = ((img.size[0] - logo.size[0]) // 2, (img.size[1] - logo.size[1]) // 2)
                        img.paste(logo, pos, logo)
                    # Custom shape (circle)
                    if shape == "circle":
                        mask = Image.new("L", img.size, 0)
                        draw = ImageDraw.Draw(mask)
                        draw.ellipse((0, 0, img.size[0], img.size[1]), fill=255)
                        img.putalpha(mask)
                    buf = io.BytesIO()
                    img.save(buf, format=fmt.upper())
                    img_data = base64.b64encode(buf.getvalue()).decode()
            except Exception as e:
                error = _("Error generating QR code: ") + str(e)
        # QR Reader
        elif "qr_image" in request.files:
            qr_image = request.files["qr_image"]
            if qr_image and qr_image.filename:
                try:
                    img = Image.open(qr_image)
                    decoded = qr_decode(img)
                    qr_result = [d.data.decode() for d in decoded] if decoded else [_("No QR code found.")]
                except Exception as e:
                    qr_result = [_("Error reading QR code: ") + str(e)]
        else:
            error = _("No data or image provided.")

    return render_template(
        "tools/qr_code_tools.html",
        img_data=img_data,
        qr_result=qr_result,
        error=error,
        _=_
    )

# --- Daily Quotes (tool) Route ---
@app.route("/tools/daily-quotes")
def daily_quotes():
    try:
        r = requests.get("https://zenquotes.io/api/random")
        quote = r.json()[0]
        quotes = [f"{quote['q']} — {quote['a']}"]
    except Exception:
        quotes = [_("Could not fetch quote. Try again later.")]
    return render_template("tools/daily_quotes.html", quotes=quotes, _=_)

# --- Daily Questions (tool) Route ---
@app.route("/tools/daily-questions")
def daily_questions():
    try:
        r = requests.get("https://opentdb.com/api.php?amount=5&type=multiple")
        data = r.json()
        questions = [q["question"] for q in data.get("results", [])]
    except Exception:
        questions = [_("Could not fetch questions. Try again later.")]
    return render_template("tools/daily_questions.html", questions=questions, _=_)

# --- PDF Tools (tool) Route ---
@app.route("/tools/pdf-tools", methods=["GET", "POST"])
def pdf_tools():
    import PyPDF2, io, os, uuid
    from werkzeug.utils import secure_filename
    from flask import send_file
    result = None
    error = None
    if request.method == "POST":
        files = request.files.getlist("file")
        action = request.form.get("action")
        password = request.form.get("password")
        watermark_text = request.form.get("watermark_text")
        rotate_angle = request.form.get("rotate_angle")
        reorder = request.form.get("reorder")
        try:
            # Save all uploaded files
            pdf_paths = []
            for file in files:
                if file and file.filename.endswith(".pdf"):
                    filename = secure_filename(file.filename)
                    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(path)
                    pdf_paths.append(path)
            # Merge
            if action == "merge":
                writer = PyPDF2.PdfWriter()
                for path in pdf_paths:
                    reader = PyPDF2.PdfReader(path)
                    for page in reader.pages:
                        writer.add_page(page)
                out_path = os.path.join(app.config['UPLOAD_FOLDER'], f"merged_{uuid.uuid4().hex}.pdf")
                with open(out_path, "wb") as f:
                    writer.write(f)
                result = url_for('static', filename=f"uploads/{os.path.basename(out_path)}")
            # Split
            elif action == "split":
                split_links = []
                for path in pdf_paths:
                    reader = PyPDF2.PdfReader(path)
                    for i, page in enumerate(reader.pages):
                        writer = PyPDF2.PdfWriter()
                        writer.add_page(page)
                        out_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{os.path.splitext(os.path.basename(path))[0]}_page_{i+1}.pdf")
                        with open(out_path, "wb") as f:
                            writer.write(f)
                        split_links.append(url_for('static', filename=f"uploads/{os.path.basename(out_path)}"))
                result = split_links
            # Compress (dummy: just re-save)
            elif action == "compress":
                for path in pdf_paths:
                    reader = PyPDF2.PdfReader(path)
                    writer = PyPDF2.PdfWriter()
                    for page in reader.pages:
                        writer.add_page(page)
                    out_path = os.path.join(app.config['UPLOAD_FOLDER'], f"compressed_{uuid.uuid4().hex}.pdf")
                    with open(out_path, "wb") as f:
                        writer.write(f)
                    result = url_for('static', filename=f"uploads/{os.path.basename(out_path)}")
            # Extract Images
            elif action == "extract_images":
                import pdfplumber, base64
                images = []
                for path in pdf_paths:
                    with pdfplumber.open(path) as pdf:
                        for page in pdf.pages:
                            for img in page.images:
                                im = page.to_image()
                                cropped = im.crop((img["x0"], img["top"], img["x1"], img["bottom"])).original
                                buf = io.BytesIO()
                                cropped.save(buf, format="PNG")
                                images.append(base64.b64encode(buf.getvalue()).decode())
                result = images
            # Convert to Word
            elif action == "to_word":
                from pdf2docx import Converter
                links = []
                for path in pdf_paths:
                    docx_path = path.replace(".pdf", ".docx")
                    cv = Converter(path)
                    cv.convert(docx_path, start=0, end=None)
                    cv.close()
                    links.append(url_for('static', filename=f"uploads/{os.path.basename(docx_path)}"))
                result = links
            # Convert to Excel
            elif action == "to_excel":
                # Placeholder: Use tabula-py or camelot for real extraction
                result = "Excel conversion coming soon!"
            # Add Password
            elif action == "add_password":
                for path in pdf_paths:
                    reader = PyPDF2.PdfReader(path)
                    writer = PyPDF2.PdfWriter()
                    for page in reader.pages:
                        writer.add_page(page)
                    out_path = os.path.join(app.config['UPLOAD_FOLDER'], f"protected_{uuid.uuid4().hex}.pdf")
                    writer.encrypt(password)
                    with open(out_path, "wb") as f:
                        writer.write(f)
                    result = url_for('static', filename=f"uploads/{os.path.basename(out_path)}")
            # Remove Password
            elif action == "remove_password":
                for path in pdf_paths:
                    reader = PyPDF2.PdfReader(path, password=password)
                    writer = PyPDF2.PdfWriter()
                    for page in reader.pages:
                        writer.add_page(page)
                    out_path = os.path.join(app.config['UPLOAD_FOLDER'], f"unprotected_{uuid.uuid4().hex}.pdf")
                    with open(out_path, "wb") as f:
                        writer.write(f)
                    result = url_for('static', filename=f"uploads/{os.path.basename(out_path)}")
            # Rotate
            elif action == "rotate":
                for path in pdf_paths:
                    reader = PyPDF2.PdfReader(path)
                    writer = PyPDF2.PdfWriter()
                    for page in reader.pages:
                        page.rotate(int(rotate_angle))
                        writer.add_page(page)
                    out_path = os.path.join(app.config['UPLOAD_FOLDER'], f"rotated_{uuid.uuid4().hex}.pdf")
                    with open(out_path, "wb") as f:
                        writer.write(f)
                    result = url_for('static', filename=f"uploads/{os.path.basename(out_path)}")
            # Watermark
            elif action == "watermark":
                # Placeholder: Add watermark logic here
                result = "Watermarking coming soon!"
            # Reorder
            elif action == "reorder":
                # Placeholder: Add reorder logic here
                result = "Reordering coming soon!"
            else:
                error = "Invalid action."
        except Exception as e:
            error = f"Error: {e}"
    return render_template("tools/pdf_tools.html", result=result, error=error)

# --- Voice-to-Text (tool) Route ---
@app.route("/tools/voice-to-text", methods=["GET", "POST"])
def voice_to_text():
    result = None
    if request.method == "POST":
        file = request.files.get("audio")
        if file and allowed_file(file.filename, ["audio"]):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            # Convert speech to text using Google Cloud Speech-to-Text
            try:
                from google.cloud import speech
                client = speech.SpeechClient()
                with open(filepath, "rb") as audio_file:
                    content = audio_file.read()
                audio = speech.RecognitionAudio(content=content)
                config = speech.RecognitionConfig(
                    encoding=speech.RecognitionConfig.AudioEncoding.LINEAR16,
                    sample_rate_hertz=16000,
                    language_code="en-US",
                )
                response = client.recognize(config=config, audio=audio)
                for result in response.results:
                    result = result.alternatives[0].transcript
            except Exception as e:
                result = f"Error: {e}"
    return render_template("tools/voice_to_text.html", result=result)

# --- Text-to-Speech (tool) Route ---
@app.route("/tools/text-to-speech", methods=["GET", "POST"])
def text_to_speech():
    import os, uuid
    result = None
    error = None
    if request.method == "POST":
        text = request.form.get("text", "")
        lang = request.form.get("lang", "en")
        try:
            from gtts import gTTS
            audio_dir = os.path.join("static", "audio")
            os.makedirs(audio_dir, exist_ok=True)
            filename = os.path.join(audio_dir, f"{uuid.uuid4()}.mp3")
            tts = gTTS(text=text, lang=lang)
            tts.save(filename)
            result = url_for('static', filename=f"audio/{os.path.basename(filename)}")
        except Exception as e:
            error = f"Error: {e}"
    return render_template("tools/text_to_speech.html", result=result, error=error)

# --- Mind-maps/Flowcharts (tool) Route ---
@app.route("/tools/mind-maps")
def mind_maps():
    return render_template("tools/mind_maps.html")

# --- Code Formatter (tool) Route ---
@app.route("/tools/code-formatter", methods=["GET", "POST"])
def code_formatter():
    result = None
    code = ""
    if request.method == "POST":
        code = request.form.get("code", "")
        if code:
            try:
                # Format code using Black
                from black import format_file_contents, FileMode
                formatted, _ = format_file_contents(code, fast=True, mode=FileMode())
                result = formatted
            except Exception as e:
                result = f"Error: {e}"
    return render_template("tools/code_formatter.html", result=result, code=code)

# --- Expense Tracker (tool) Route ---
@app.route("/tools/expense-tracker", methods=["GET", "POST"])
@login_required
def expense_tracker():
    if request.method == "POST":
        date = request.form.get("date")
        category = request.form.get("category")
        amount = request.form.get("amount")
        description = request.form.get("description")
        # Save to user's expenses (JSON field)
        user = User.query.get(session["user_id"])
        expenses = user.expenses or []
        expenses.append({
            "date": date,
            "category": category,
            "amount": float(amount),
            "description": description
        })
        user.expenses = expenses
        db.session.commit()
        flash("Expense added!", "success")
        return redirect(url_for("expense_tracker"))
    user = User.query.get(session["user_id"])
    expenses = user.expenses if user else []
    return render_template("tools/expense_tracker.html", expenses=expenses)

# --- Budget Tracker (tool) Route ---
@app.route("/tools/budget-tracker", methods=["GET", "POST"])
@login_required
def budget_tracker():
    if request.method == "POST":
        month = request.form.get("month")
        budget = request.form.get("budget")
        # Save to user's budget (JSON field)
        user = User.query.get(session["user_id"])
        user.budget = { "month": month, "budget": float(budget) }
        db.session.commit()
        flash("Budget saved!", "success")
        return redirect(url_for("budget_tracker"))
    user = User.query.get(session["user_id"])
    budget = user.budget if user else {}
    return render_template("tools/budget_tracker.html", budget=budget)

# --- Grocery List Manager (tool) Route ---
@app.route("/tools/grocery-list", methods=["GET", "POST"])
@login_required
def grocery_list():
    if request.method == "POST":
        item = request.form.get("item")
        quantity = request.form.get("quantity")
        # Save to user's grocery list (JSON field)
        user = User.query.get(session["user_id"])
        grocery_list = user.grocery_list or []
        grocery_list.append({
            "item": item,
            "quantity": quantity
        })
        user.grocery_list = grocery_list
        db.session.commit()
        flash("Item added to grocery list!", "success")
        return redirect(url_for("grocery_list"))
    user = User.query.get(session["user_id"])
    grocery_list = user.grocery_list if user else []
    return render_template("tools/grocery_list.html", grocery_list=grocery_list)

# --- Health Tracker (tool) Route ---
@app.route("/tools/health-tracker", methods=["GET", "POST"])
@login_required
def health_tracker():
    if request.method == "POST":
        date = request.form.get("date")
        weight = request.form.get("weight")
        height = request.form.get("height")
        bmi = request.form.get("bmi")
        # Save to user's health data (JSON field)
        user = User.query.get(session["user_id"])
        health_data = user.health_data or []
        health_data.append({
            "date": date,
            "weight": float(weight),
            "height": float(height),
            "bmi": float(bmi)
        })
        user.health_data = health_data
        db.session.commit()
        flash("Health data added!", "success")
        return redirect(url_for("health_tracker"))
    user = User.query.get(session["user_id"])
    health_data = user.health_data if user else []
    return render_template("tools/health_tracker.html", health_data=health_data)

# --- Random Generator (tool) Route ---
@app.route("/tools/random-generator")
def random_generator():
    return render_template("tools/random_generator.html")

# --- Collaborative Notes (tool) Route ---
@app.route("/tools/collaborative-notes", methods=["GET", "POST"])
@login_required
def collaborative_notes():
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        # Save to user's notes (JSON field)
        user = User.query.get(session["user_id"])
        notes = user.notes or []
        notes.append({
            "title": title,
            "content": content
        })
        user.notes = notes
        db.session.commit()
        flash("Note added!", "success")
        return redirect(url_for("collaborative_notes"))
    user = User.query.get(session["user_id"])
    notes = user.notes if user else []
    return render_template("tools/collaborative_notes.html", notes=notes)

# --- Basic Drawing (tool) Route ---
@app.route("/tools/basic-drawing")
def basic_drawing():
    return render_template("tools/basic_drawing.html")

# --- Stock/Market Tracker (tool) Route ---
@app.route("/tools/stock-market-tracker", methods=["GET", "POST"])
@login_required
def stock_market_tracker():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        # Save to user's stock/market data (JSON field)
        user = User.query.get(session["user_id"])
        market_data = user.market_data or []
        market_data.append({
            "symbol": symbol
        })
        user.market_data = market_data
        db.session.commit()
        flash("Stock/Market data added!", "success")
        return redirect(url_for("stock_market_tracker"))
    user = User.query.get(session["user_id"])
    market_data = user.market_data if user else []
    return render_template("tools/stock_market_tracker.html", market_data=market_data)

# --- Bookmark Manager (tool) Route ---
@app.route("/tools/bookmark-manager", methods=["GET", "POST"])
@login_required
def bookmark_manager():
    if request.method == "POST":
        title = request.form.get("title")
        url = request.form.get("url")
        # Save to user's bookmarks (JSON field)
        user = User.query.get(session["user_id"])
        bookmarks = user.bookmarks or []
        bookmarks.append({
            "title": title,
            "url": url
        })
        user.bookmarks = bookmarks
        db.session.commit()
        flash("Bookmark added!", "success")
        return redirect(url_for("bookmark_manager"))
    user = User.query.get(session["user_id"])
    bookmarks = user.bookmarks if user else []
    return render_template("tools/bookmark_manager.html", bookmarks=bookmarks)

# --- World Clock (tool) Route ---
@app.route("/tools/world-clock")
def world_clock():
    return render_template("tools/world_clock.html", bigdatacloud_api_key=BIGDATACLOUD_API_KEY)

# --- Periodic Table (tool) Route ---
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

# --- Flashcard Test (tool) Route ---
@app.route("/tools/flashcard-test", methods=["GET", "POST"])
@login_required
def flashcard_test():
    if request.method == "POST":
        set_name = request.form.get("set_name")
        action = request.form.get("action")
        if action == "start":
            session["flashcard_test_set"] = set_name
            session["flashcard_test_index"] = 0
            session.modified = True
            return redirect(url_for("flashcard_test"))
        elif action == "next":
            index = session.get("flashcard_test_index", 0)
            session["flashcard_test_index"] = index + 1
            session.modified = True
            return redirect(url_for("flashcard_test"))
        elif action == "finish":
            session.pop("flashcard_test_set", None)
            session.pop("flashcard_test_index", None)
            session.modified = True
            flash("Test finished!", "success")
            return redirect(url_for("flashcards"))
    set_name = session.get("flashcard_test_set")
    index = session.get("flashcard_test_index", 0)
    flashcards = []
    if set_name:
        flashcards = session["flashcard_sets"].get(set_name, [])
    current_card = flashcards[index] if index < len(flashcards) else None
    return render_template("tools/flashcard_test.html", flashcards=flashcards, current_card=current_card, set_name=set_name)

# --- AI Chatbot (tool) Route ---
@app.route("/tools/ai-chatbot", methods=["GET", "POST"])
def ai_chatbot():
    response = None
    if request.method == "POST":
        user_input = request.form.get("user_input", "").strip()
        if user_input:
            try:
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": user_input}],
                    max_tokens=150,
                    temperature=0.7,
                )
                response = response.choices[0].message.content.strip()
            except Exception as e:
                response = f"Error: {e}"
    return render_template("tools/ai_chatbot.html", response=response)

# --- Text Case Convertor (tool) Route ---
@app.route("/tools/text-case-convertor", methods=["GET", "POST"])
def text_case_convertor():
    text = ""
    result = ""
    if request.method == "POST":
        text = request.form.get("text", "")
        case = request.form.get("case", "")
        if case == "upper":
            result = text.upper()
        elif case == "lower":
            result = text.lower()
        elif case == "title":
            result = text.title()
        elif case == "sentence":
            result = text.capitalize()
        elif case == "snake":
            result = "_".join(text.lower().split())
        elif case == "kebab":
            result = "-".join(text.lower().split())
        elif case == "camel":
            words = text.split()
            result = words[0].lower() + "".join(w.capitalize() for w in words[1:])
        elif case == "invert":
            result = text.swapcase()
        else:
            result = text
    return render_template("tools/text_case_convertor.html", text=text, result=result, _=_)

# --- Markdown Previewer (tool) Route ---
@app.route("/tools/markdown-previewer")
def markdown_previewer():
    return render_template("tools/markdown_previewer.html", _=_)

# --- Password Generator (tool) Route ---
@app.route("/tools/password-generator", methods=["GET", "POST"])
def password_generator():
    password = ""
    length = 12
    uppercase = numbers = symbols = True
    exclude = ""
    batch = 1
    if request.method == "POST":
        length = int(request.form.get("length", 12))
        uppercase = "uppercase" in request.form
        numbers = "numbers" in request.form
        symbols = "symbols" in request.form
        exclude = request.form.get("exclude", "")
        batch = int(request.form.get("batch", 1))
        charset = string.ascii_lowercase
        if uppercase:
            charset += string.ascii_uppercase
        if numbers:
            charset += string.digits
        if symbols:
            charset += string.punctuation
        charset = "".join(c for c in charset if c not in exclude)
        passwords = []
        for _ in range(batch):
            passwords.append("".join(random.choice(charset) for _ in range(length)))
        password = "\n".join(passwords)
    return render_template("tools/password_generator.html", password=password, length=length, uppercase=uppercase, numbers=numbers, symbols=symbols)

# --- Music/Audio Player (tool) Route ---
@app.route("/tools/music-audio-player", methods=["GET", "POST"])
def music_audio_player():
    if "audio_queue" not in session:
        session["audio_queue"] = []
    if request.method == "POST":
        files = request.files.getlist("audio_files")
        for file in files:
            if file and file.filename.lower().endswith((".mp3", ".wav", ".ogg", ".m4a")):
                filename = secure_filename(file.filename)
                path = os.path.join(app.config['UPLOAD_FOLDER'], 'music', filename)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                file.save(path)
                session["audio_queue"].append({
                    "name": filename,
                    "url": url_for('static', filename=f"uploads/music/{filename}")
                })
        session.modified = True
        flash("Files uploaded!", "success")
    return render_template("tools/music_audio_player.html", audio_queue=session["audio_queue"])

# -- Text Counter (tool) Route ---
@app.route("/tools/text-counter", methods=["GET", "POST"])
def text_counter():
    text = ""
    if request.method == "POST":
        file = request.files.get("file")
        if file and file.filename.lower().endswith((".txt",)):
            text = file.read().decode("utf-8")
        else:
            text = request.form.get("text", "")
    return render_template("tools/text_counter.html", text=text)

# Text Reverser (tool) Route ---
@app.route("/tools/text-reverser", methods=["GET", "POST"])
def text_reverser():
    text = result = ""
    if request.method == "POST":
        text = request.form.get("text", "")
        result = text[::-1]
    return render_template("tools/text_reverser.html", text=text, result=result)

# --- Text Difference Checker (tool) Route ---
@app.route("/tools/text-difference-checker", methods=["GET", "POST"])
def text_difference_checker():
    a = b = diff = ""
    if request.method == "POST":
        a = request.form.get("a", "")
        b = request.form.get("b", "")
        import difflib
        diff = "\n".join(difflib.unified_diff(a.splitlines(), b.splitlines(), lineterm=""))
    return render_template("tools/text_difference_checker.html", a=a, b=b, diff=diff)

# --- Plagiarism Checker (tool) Route ---
@app.route("/tools/plagiarism-checker", methods=["GET", "POST"])
def plagiarism_checker():
    text = result = ""
    if request.method == "POST":
        text = request.form.get("text", "")
        # For demo: just say "No plagiarism detected"
        result = "No plagiarism detected (demo)."
    return render_template("tools/plagiarism_checker.html", text=text, result=result)

# --- AI Checker (tool) Route ---
@app.route("/tools/ai-checker", methods=["GET", "POST"])
def ai_checker():
    text = result = ""
    if request.method == "POST":
        text = request.form.get("text", "")
        # For demo: just say "Likely human-written"
        result = "Likely human-written (demo)."
    return render_template("tools/ai_checker.html", text=text, result=result)

# --- Morse Code Tools (tool) Route ---
@app.route("/tools/morse-code-tools", methods=["GET", "POST"])
def morse_code_tools():
    text = result = ""
    mode = "encode"
    MORSE = { 'A':'.-', 'B':'-...', 'C':'-.-.', 'D':'-..', 'E':'.', 'F':'..-.', 'G':'--.', 'H':'....', 'I':'..', 'J':'.---', 'K':'-.-', 'L':'.-..', 'M':'--', 'N':'-.', 'O':'---', 'P':'.--.', 'Q':'--.-', 'R':'.-.', 'S':'...', 'T':'-', 'U':'..-', 'V':'...-', 'W':'.--', 'X':'-..-', 'Y':'-.--', 'Z':'--..', '1':'.----', '2':'..---', '3':'...--', '4':'....-', '5':'.....', '6':'-....', '7':'--...', '8':'---..', '9':'----.', '0':'-----', ', ':'--..--', '.':'.-.-.-', '?':'..--..', '/':'-..-.', '-':'-....-', '(':'-.--.', ')':'-.--.-'}
    if request.method == "POST":
        text = request.form.get("text", "")
        mode = request.form.get("mode", "encode")
        if mode == "encode":
            result = " ".join(MORSE.get(c.upper(), c) for c in text)
        else:
            inv = {v: k for k, v in MORSE.items()}
            result = "".join(inv.get(c, c) for c in text.split())
    return render_template("tools/morse_code_tools.html", text=text, result=result, mode=mode)

# --- Random Name Picker (tool) Route ---
@app.route("/tools/random-name-picker", methods=["GET", "POST"])
def random_name_picker():
    names = result = ""
    if request.method == "POST":
        names = request.form.get("names", "")
        import random
        name_list = [n.strip() for n in names.split(",") if n.strip()]
        result = random.choice(name_list) if name_list else ""
    return render_template("tools/random_name_picker.html", names=names, result=result)

# --- Dice Roller (tool) Route ---
@app.route("/tools/dice", methods=["GET", "POST"])
def dice():
    num = int(request.form.get("num", 1))
    sides = int(request.form.get("sides", 6))
    rolls = []
    if request.method == "POST":
        import random
        rolls = [random.randint(1, sides) for _ in range(num)]
    return render_template("tools/dice.html", num=num, sides=sides, rolls=rolls)

# --- Coin Toss (tool) Route ---
@app.route("/tools/coin-toss", methods=["GET", "POST"])
def coin_toss():
    result = ""
    if request.method == "POST":
        import random
        result = random.choice(["Heads", "Tails"])
    return render_template("tools/coin_toss.html", result=result)

# --- Main Application Setup ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))