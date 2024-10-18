import os
import yaml
import socket
import hashlib
import logging
import requests
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from clickhouse_driver import Client
from flask_migrate import Migrate
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, IntegerField, PasswordField
from wtforms.validators import DataRequired, Email, NumberRange, Length
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
# Load configuration from YAML file
def load_config():
    try:
        with open("config.yml", "r") as config_file:
            return yaml.safe_load(config_file)
    except FileNotFoundError:
        logger.error("Configuration file not found.")
        return None
    except yaml.YAMLError as e:
        logger.error(f"Error parsing configuration file: {e}")
        return None



config = load_config()

if not config:
    raise RuntimeError("Failed to load configuration. Application cannot start.")

# Initialize Flask app
app = Flask(__name__)

# Ensure SECRET_KEY is set
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY is not set in environment variables.")
app.config["SECRET_KEY"] = secret_key

basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL") or "sqlite:///" + os.path.join(
    basedir, "no_consent.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)  # Session timeout

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize Flask-Limiter for rate limiting
limiter = Limiter(app=app, key_func=get_remote_address)

# ClickHouse configuration
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", 9000))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_DATABASE = os.environ.get("CLICKHOUSE_DATABASE", "default")

# Token cache for Moodle API tokens
token_cache = {}

# Load school configuration from YAML
def get_school_info(school):
    return config["schools"].get(school.lower())

# Helper function to retrieve Moodle API base URL, API key, and secret
def get_moodle_api_base_url(school):
    school_info = get_school_info(school)
    if not school_info:
        logger.error(f"School '{school}' is not found in the configuration.")
        return None
    return school_info["moodle_api_base_url"]

def get_moodle_api_key_and_secret(school):
    school_info = get_school_info(school)
    if not school_info:
        logger.error(f"School '{school}' is not found in the configuration.")
        return None, None
    return school_info["api_key"], school_info["api_secret"]

# Ensure the Flask application does not crash if Moodle API credentials are missing
def get_moodle_api_token(school):
    # Implement token caching with expiration
    if school in token_cache:
        token_info = token_cache[school]
        if token_info["expires_at"] > datetime.utcnow():
            return token_info["token"]

    api_key, api_secret = get_moodle_api_key_and_secret(school)
    if not api_key or not api_secret:
        logger.error(f"API Key or Secret is missing for school '{school}'")
        return None

    moodle_api_base_url = get_moodle_api_base_url(school)
    if not moodle_api_base_url:
        return None

    token_url = f"{moodle_api_base_url}/api/token"
    try:
        response = requests.post(
            token_url,
            json={"client_id": api_key, "client_secret": api_secret},
            timeout=10,
        )
        response.raise_for_status()
        try:
            json_response = response.json()
        except ValueError as e:
            logger.error(f"Failed to parse JSON response for token: {e}")
            return None

        token = json_response.get("access_token")
        expires_in = json_response.get("expires_in", 3600)  # Default to 1 hour
        token_cache[school] = {
            "token": token,
            "expires_at": datetime.utcnow() + timedelta(seconds=expires_in),
        }
        return token
    except requests.RequestException as e:
        logger.error(f"Failed to get Moodle API token for {school}: {e}")
        return None

# Fetch Moodle IDs with error handling for invalid responses
def get_moodle_ids(emails, school):
    moodle_api_base_url = get_moodle_api_base_url(school)
    if not moodle_api_base_url:
        flash(f"Failed to get Moodle API base URL for school '{school}'")
        return []

    token = get_moodle_api_token(school)
    if not token:
        flash(f"Failed to get Moodle API token for school '{school}'")
        return []

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    get_ids_url = f"{moodle_api_base_url}/api/get_moodle_ids"

    try:
        response = requests.get(
            get_ids_url,
            params={"emails": ",".join(emails)},
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
        try:
            json_response = response.json()
        except ValueError as e:
            logger.error(f"Failed to parse JSON response for Moodle IDs: {e}")
            flash("Invalid response from Moodle API")
            return []

        moodle_ids = json_response.get("moodle_ids", [])
        if not moodle_ids:
            logger.error(f"No Moodle IDs found for emails: {emails}")
        return moodle_ids
    except requests.RequestException as e:
        logger.error(f"Failed to get Moodle IDs for school '{school}': {e}")
        return []

def hash_moodleid(moodle_id, encryption_salt, school):
    if not encryption_salt:
        raise ValueError("ENCRYPTION_SALT is not set in the environment variables")

    hasher = hashlib.sha256()
    hasher.update(encryption_salt.encode("utf-8"))
    hasher.update(school.encode("utf-8"))
    hasher.update(str(moodle_id).encode("utf-8"))
    return hasher.hexdigest()

def clickhouse_operation(operation, school, email, moodle_id, year):
    encryption_salt = os.environ.get("ENCRYPTION_SALT")
    if not encryption_salt:
        logger.error("ENCRYPTION_SALT is not set in the environment variables")
        return False

    hashed_moodle_id = hash_moodleid(moodle_id, encryption_salt, school)
    client = None  # Initialize client to None

    try:
        client = Client(
            host=CLICKHOUSE_HOST,
            port=CLICKHOUSE_PORT,
            user=CLICKHOUSE_USER,
            password=CLICKHOUSE_PASSWORD,
            database=CLICKHOUSE_DATABASE,
        )

        if operation in ["add", "edit"]:
            result = client.execute(
                "SELECT MAX(version) FROM moodle_ids WHERE email = %(email)s",
                {"email": email},
            )
            current_version = result[0][0] if result and result[0][0] is not None else 0

            client.execute(
                """
                INSERT INTO moodle_ids 
                (school, email, moodleid, hashed_moodle_id, version, year) 
                VALUES (%(school)s, %(email)s, %(moodleid)s, %(hashed_moodle_id)s, %(version)s, %(year)s)
                """,
                {
                    "school": school,
                    "email": email,
                    "moodleid": moodle_id,
                    "hashed_moodle_id": hashed_moodle_id,
                    "version": current_version + 1,
                    "year": year,
                },
            )
            logger.info(f"{'Added' if operation == 'add' else 'Updated'} record in ClickHouse: {email}, {moodle_id}")

        elif operation == "delete":
            # Mark as inactive instead of deleting
            client.execute(
                """
                ALTER TABLE moodle_ids UPDATE is_active = 0 WHERE email = %(email)s
                """,
                {"email": email},
            )
            logger.info(f"Marked record as inactive in ClickHouse: {email}")

        return True
    except Exception as e:
        logger.error(f"Failed to perform {operation} operation in ClickHouse: {e}")
        return False
    finally:
        if client:
            client.disconnect()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        # Use a stronger hashing algorithm like bcrypt
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class NoConsent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    edited = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    email = db.Column(db.String(120), nullable=False, unique=True)
    school = db.Column(db.String(120), nullable=False)
    moodle_id = db.Column(db.String(50))
    year = db.Column(db.Integer, nullable=False, default=datetime.utcnow().year)

# WTForms for input validation
class RecordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    school = StringField("School", validators=[DataRequired(), Length(max=120)])
    year = IntegerField(
        "Year", validators=[DataRequired(), NumberRange(min=2000, max=2100)]
    )
    def validate_school(self, field):
        if field.data not in config["schools"].keys():
            raise ValidationError("Invalid school selected")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])

class DeleteForm(FlaskForm):
    pass

@app.route("/add", methods=["GET", "POST"])
@login_required
def add_record():
    form = RecordForm()
    schools = [(key, school['name']) for key, school in config['schools'].items()]
    current_year = datetime.now().year
    years = range(current_year - 5, current_year + 6)  # 5 years before and after current year
    
    if form.validate_on_submit():
        email = form.email.data
        school = form.school.data
        year = form.year.data

        moodle_ids = get_moodle_ids([email], school)
        if not moodle_ids:
            flash(f"Failed to retrieve Moodle ID for {email} at {school}")
            return redirect(url_for("add_record"))

        moodle_id = moodle_ids[0]

        try:
            if clickhouse_operation("add", school, email, moodle_id, int(year)):
                new_record = NoConsent(
                    email=email, school=school, moodle_id=moodle_id, year=int(year)
                )
                db.session.add(new_record)
                db.session.commit()
                flash("Record added successfully")
                return redirect(url_for("index"))
            else:
                db.session.rollback()
                flash("Failed to update ClickHouse")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to add record to SQLite: {e}")
            flash("An error occurred while adding the record")

    return render_template("add.html", form=form, schools=schools, years=years)



@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_record(id):
    record = NoConsent.query.get_or_404(id)
    form = RecordForm(obj=record)
    schools = [(key, school['name']) for key, school in config['schools'].items()]
    current_year = datetime.now().year
    years = range(current_year - 5, current_year + 6)  # 5 years before and after current year
    
    if form.validate_on_submit():
        email = form.email.data
        school = form.school.data
        year = form.year.data

        moodle_ids = get_moodle_ids([email], school)
        if not moodle_ids:
            flash(f"Failed to retrieve Moodle ID for {email} at {school}")
            return redirect(url_for("edit_record", id=id))

        moodle_id = moodle_ids[0]

        try:
            if clickhouse_operation("edit", school, email, moodle_id, int(year)):
                record.email = email
                record.school = school
                record.moodle_id = moodle_id
                record.year = int(year)
                db.session.commit()
                flash("Record updated successfully")
                return redirect(url_for("index"))
            else:
                db.session.rollback()
                flash("Failed to update ClickHouse")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to update record in SQLite: {e}")
            flash("An error occurred while updating the record")
    
    return render_template("edit.html", form=form, record=record, schools=schools, years=years)


@app.route("/delete/<int:id>", methods=["POST"])
@login_required
def delete_record(id):
    record = NoConsent.query.get_or_404(id)

    # Begin database transaction
    try:
        if clickhouse_operation("delete", record.school, record.email, record.moodle_id, record.year):
            db.session.delete(record)
            db.session.commit()
            flash("Record deleted successfully")
        else:
            db.session.rollback()
            flash("Failed to delete from ClickHouse")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to delete record from SQLite: {e}")
        flash("An error occurred while deleting the record")

    return redirect(url_for("index"))

@app.route("/") 
@login_required
def index():
    records = NoConsent.query.all()
    delete_form = DeleteForm()
    return render_template("index.html", records=records, form=delete_form)

# Apply rate limiting to the login route
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("50 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("index"))
        flash("Invalid username or password")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template("500.html"), 500

def create_admin():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            admin_password = os.environ.get("ADMIN_PASSWORD")
            if not admin_password:
                raise RuntimeError("ADMIN_PASSWORD is not set in environment variables.")
            admin = User(username="admin")
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
            logger.info("Admin user created successfully.")

if __name__ == "__main__":
    create_admin()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
