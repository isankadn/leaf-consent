# app.py
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from dotenv import load_dotenv
import requests
from clickhouse_driver import Client
import logging
import hashlib
from datetime import datetime
from flask_migrate import Migrate

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
    'sqlite:///' + os.path.join(basedir, 'no_consent.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ClickHouse configuration
CLICKHOUSE_HOST = os.environ.get('CLICKHOUSE_HOST', 'localhost')
CLICKHOUSE_PORT = int(os.environ.get('CLICKHOUSE_PORT', 9000))
CLICKHOUSE_USER = os.environ.get('CLICKHOUSE_USER', 'default')
CLICKHOUSE_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')
CLICKHOUSE_DATABASE = os.environ.get('CLICKHOUSE_DATABASE', 'default')

# Moodle API configuration
SK_MOODLE_API_BASE_URL = os.environ.get('SK_MOODLE_API_BASE_URL', 'localhost')
MOODLE_API_TOKEN_URL = f'{SK_MOODLE_API_BASE_URL}/api/token'
MOODLE_API_GET_IDS_URL = f'{SK_MOODLE_API_BASE_URL}/api/get_moodle_ids'

# API Key and Secret
SK_API_KEY = os.environ.get('SK_API_KEY')
SK_API_SECRET = os.environ.get('SK_API_SECRET')

SCHOOLS = [
    ('saikyo', 'Saikyo'),
    ('dcat', 'Dcat'),
    ('setsuryo', 'Setsuryo'),
    ('kawaminami', 'Kawaminami'),
    ('hikone', 'Hikone'),
    ('kozu', 'Kozu'),
    ('otsu', 'Otsu'),
    ('zeze', 'Zeze')
]

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class NoConsent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    edited = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    email = db.Column(db.String(120), nullable=False, unique=True)
    school = db.Column(db.String(120), nullable=False)
    moodle_id = db.Column(db.String(20))
    year = db.Column(db.Integer, nullable=False)  

def get_moodle_api_token():
    if not SK_API_KEY or not SK_API_SECRET:
        logger.error("API Key or Secret is missing")
        return None

    try:
        response = requests.post(
            MOODLE_API_TOKEN_URL,
            json={"client_id": SK_API_KEY, "client_secret": SK_API_SECRET},
            timeout=10
        )
        response.raise_for_status()
        print(response.json())
        return response.json().get('access_token')
    except requests.RequestException as e:
        logger.error(f"Failed to get Moodle API token: {e}")
        return None

def get_moodle_ids(emails):
    token = get_moodle_api_token()
    if not token:
        logger.error("Failed to obtain Moodle API token")
        return []

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(
            MOODLE_API_GET_IDS_URL,
            params={'emails': ','.join(emails)},
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        return response.json()  # Return the full response
    except requests.RequestException as e:
        logger.error(f"Failed to get Moodle IDs: {e}")
        return []

def hash_moodleid(moodle_id, encryption_salt, school):
    if not encryption_salt:
        raise ValueError("ENCRYPTION_SALT is not set in the environment variables")
    
    hasher = hashlib.sha256()
    hasher.update(encryption_salt.encode('utf-8'))
    hasher.update(school.encode('utf-8'))
    hasher.update(str(moodle_id).encode('utf-8'))
    return hasher.hexdigest()

def clickhouse_operation(operation, school, email, moodle_id, year):
    encryption_salt = os.environ.get('ENCRYPTION_SALT')
    if not encryption_salt:
        logger.error("ENCRYPTION_SALT is not set in the environment variables")
        return False

    hashed_moodle_id = hash_moodleid(moodle_id, encryption_salt, school)

    try:
        client = Client(
            host=CLICKHOUSE_HOST,
            port=CLICKHOUSE_PORT,
            user=CLICKHOUSE_USER,
            password=CLICKHOUSE_PASSWORD,
            database=CLICKHOUSE_DATABASE
        )

        if operation in ['add', 'edit']:
            # Get the current max version for this email
            result = client.execute(
                "SELECT MAX(version) FROM moodle_ids WHERE email = %(email)s",
                {'email': email}
            )
            current_version = result[0][0] if result[0][0] is not None else 0

            # Insert new record with incremented version
            client.execute(
                """
                INSERT INTO moodle_ids 
                (school, email, moodleid, hashed_moodle_id, version, year) 
                VALUES
                """,
                [(school, email, str(moodle_id), hashed_moodle_id, current_version + 1, year]
            )
            logger.info(f"{'Added' if operation == 'add' else 'Updated'} record in ClickHouse: {email}, {moodle_id}")

        elif operation == 'delete':
            client.execute(
                "ALTER TABLE moodle_ids DELETE WHERE email = %(email)s",
                {'email': email}
            )
            logger.info(f"Deleted record from ClickHouse: {email}")

        return True
    except Exception as e:
        logger.error(f"Failed to perform {operation} operation in ClickHouse: {e}")
        return False
    finally:
        client.disconnect()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
    

@app.route('/')
@login_required
def index():
    records = NoConsent.query.all()
    return render_template('index.html', records=records)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_record():
    current_year = datetime.now().year
    if request.method == 'POST':
        email = request.form.get('email')
        school = request.form.get('school')
        year = request.form.get('year')
        if email and school:
            existing_record = NoConsent.query.filter_by(email=email).first()
            if existing_record:
                flash('A record with this email already exists')
                return redirect(url_for('edit_record', id=existing_record.id))
            
            # Get Moodle ID
            moodle_ids_response = get_moodle_ids([email])
            
            # Log the response for debugging
            logger.info(f"Moodle IDs response: {moodle_ids_response}")
            
            # Check if the response is a dictionary and has 'moodle_ids' key
            if isinstance(moodle_ids_response, dict) and 'moodle_ids' in moodle_ids_response:
                moodle_ids = moodle_ids_response['moodle_ids']
                if isinstance(moodle_ids, list) and len(moodle_ids) > 0:
                    moodle_id = moodle_ids[0]
                else:
                    logger.error("No Moodle ID found in the response")
                    flash('No Moodle ID found for this email. Please try again later.')
                    return redirect(url_for('index'))
            else:
                logger.error("Unexpected response format from get_moodle_ids")
                flash('Failed to get Moodle ID. Please try again later.')
                return redirect(url_for('index'))

            # Update ClickHouse first
            if not clickhouse_operation('add', school, email, moodle_id, int(year)):
                flash('Failed to update ClickHouse. Please try again later..')
                return redirect(url_for('index'))

            # If ClickHouse update is successful, add to SQLite
            new_record = NoConsent(email=email, school=school, moodle_id=str(moodle_id), year=int(year))
            db.session.add(new_record)
            
            try:
                db.session.commit()
                flash('Record added successfully')
                return redirect(url_for('index'))
            except Exception as e:
                db.session.rollback()
                logger.error(f"Failed to add record to SQLite: {e}")
                flash('An error occurred while adding the record')
        else:
            flash('Email and school are required')
    return render_template('add.html', schools=SCHOOLS, current_year=current_year)
    
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_record(id):
    current_year = datetime.now().year
    record = NoConsent.query.get_or_404(id)
    if request.method == 'POST':
        email = request.form.get('email')
        school = request.form.get('school')
        year = request.form.get('year')
        if email and school:
            existing_record = NoConsent.query.filter(NoConsent.email == email, NoConsent.id != id).first()
            if existing_record:
                flash('A record with this email already exists')
            else:
                # Get Moodle ID
                moodle_ids_response = get_moodle_ids([email])
                
                logger.info(f"Moodle IDs response: {moodle_ids_response}")
                
                if isinstance(moodle_ids_response, dict) and 'moodle_ids' in moodle_ids_response:
                    moodle_ids = moodle_ids_response['moodle_ids']
                    if isinstance(moodle_ids, list) and len(moodle_ids) > 0:
                        moodle_id = moodle_ids[0]
                    else:
                        logger.error("No Moodle ID found in the response")
                        flash('No Moodle ID found for this email. Please try again later.')
                        return redirect(url_for('index'))
                else:
                    logger.error("Unexpected response format from get_moodle_ids")
                    flash('Failed to get Moodle ID. Please try again later.')
                    return redirect(url_for('index'))

                # Update ClickHouse
                if clickhouse_operation('edit', school, email, moodle_id, int(year)):
                    # If ClickHouse update is successful, update SQLite
                    record.email = email
                    record.school = school
                    record.moodle_id = str(moodle_id)
                    record.year = int(year)
                    try:
                        db.session.commit()
                        flash('Record updated successfully')
                        return redirect(url_for('index'))
                    except Exception as e:
                        db.session.rollback()
                        logger.error(f"Failed to update record in SQLite: {e}")
                        flash('An error occurred while updating the record')
                else:
                    flash('Failed to update ClickHouse. Please try again later.')
                    return redirect(url_for('index'))
        else:
            flash('Email and school are required')
    return render_template('edit.html', record=record, schools=SCHOOLS, current_year=current_year)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_record(id):
    record = NoConsent.query.get_or_404(id)

    if clickhouse_operation('delete', record.school, record.email, record.moodle_id):
        try:
            db.session.delete(record)
            db.session.commit()
            flash('Record deleted successfully')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to delete record from SQLite: {e}")
            flash('An error occurred while deleting the record')
    else:
        flash('Failed to delete from ClickHouse. Please try again later.')
    
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

def create_admin():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_password = os.environ.get('ADMIN_PASSWORD')
            if not admin_password:
                logger.warning("ADMIN_PASSWORD not set in .env file. Admin user not created.")
                return
            admin = User(username='admin')
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
            logger.info("Admin user created successfully.")

if __name__ == '__main__':
    create_admin()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)