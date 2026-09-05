from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_file,
    session
)

import os
import io
import uuid

from pypdf import PdfReader

from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user
)

from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

from cryptography.fernet import Fernet

from werkzeug.utils import secure_filename

from sqlalchemy import inspect

from models import db, User, VaultFile

from classifier import classify_text
from sensitivity import detect_sensitivity
from purpose import detect_purpose
from retention import recommend_retention
from ai_analyzer import ai_analyze_document


# ==========================================
# LOAD ENVIRONMENT VARIABLES
# ==========================================

load_dotenv()


# ==========================================
# FLASK APP
# ==========================================

app = Flask(__name__)


# ==========================================
# APP CONFIGURATION
# ==========================================

app.config["SECRET_KEY"] = "visionx-secret-key-change-later"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///visionx.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# ==========================================
# NORMAL DOCUMENT STORAGE
# ==========================================

UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# ==========================================
# PRIVATE VAULT STORAGE
# ==========================================

VAULT_FOLDER = "vault_storage"

app.config["VAULT_FOLDER"] = VAULT_FOLDER

os.makedirs(
    VAULT_FOLDER,
    exist_ok=True
)


# ==========================================
# VAULT ENCRYPTION KEY
# ==========================================

VAULT_ENCRYPTION_KEY = os.getenv(
    "VAULT_ENCRYPTION_KEY"
)

if not VAULT_ENCRYPTION_KEY:
    raise RuntimeError(
        "VAULT_ENCRYPTION_KEY is missing from .env"
    )


try:

    vault_fernet = Fernet(
        VAULT_ENCRYPTION_KEY.encode()
    )

except Exception:

    raise RuntimeError(
        "Invalid VAULT_ENCRYPTION_KEY in .env"
    )


# ==========================================
# DATABASE
# ==========================================

db.init_app(app)


# ==========================================
# LOGIN MANAGER
# ==========================================

login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):

    try:

        return db.session.get(
            User,
            int(user_id)
        )

    except (ValueError, TypeError):

        return None


# ==========================================
# GOOGLE OAUTH
# ==========================================

oauth = OAuth(app)

google = oauth.register(
    name="google",

    client_id=os.getenv(
        "GOOGLE_CLIENT_ID"
    ),

    client_secret=os.getenv(
        "GOOGLE_CLIENT_SECRET"
    ),

    server_metadata_url=
        "https://accounts.google.com/.well-known/openid-configuration",

    client_kwargs={
        "scope": "openid email profile"
    }
)


# ==========================================
# CREATE DATABASE + SECURITY PIN COLUMN
# ==========================================

with app.app_context():

    db.create_all()

    inspector = inspect(
        db.engine
    )

    user_columns = [
        column["name"]
        for column in inspector.get_columns("user")
    ]

    if "security_pin_hash" not in user_columns:

        with db.engine.begin() as connection:

            connection.exec_driver_sql(
                "ALTER TABLE user ADD COLUMN security_pin_hash VARCHAR(255)"
            )

        print(
            "Security PIN column added successfully."
        )


# ==========================================
# DOCUMENT ANALYSIS
# ==========================================

def analyze_file(filename):

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    reader = PdfReader(
        file_path
    )

    text = ""

    for page in reader.pages:

        text += page.extract_text() or ""


    category = classify_text(
        text
    )

    sensitivity = detect_sensitivity(
        text
    )

    purpose = detect_purpose(
        text
    )

    retention = recommend_retention(
        category,
        sensitivity,
        purpose
    )

    ai_result = ai_analyze_document(
        text
    )


    return {
        "filename": filename,

        "category": category,

        "sensitivity": sensitivity,

        "purpose": purpose,

        "retention": retention,

        "ai_type":
            ai_result["document_type"],

        "ai_confidence":
            ai_result["confidence"]
    }


# ==========================================
# LOGIN
# ==========================================

@app.route(
    "/",
    methods=["GET", "POST"]
)
def login():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard")
        )


    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )


        user = User.query.filter_by(
            email=email
        ).first()


        if user and user.check_password(
            password
        ):

            login_user(
                user
            )

            # SECURITY PIN IS NOT REQUIRED
            # DURING NORMAL LOGIN.
            #
            # User can create the PIN later
            # intentionally when needed.

            return redirect(
                url_for("dashboard")
            )


        return render_template(
            "login.html",
            error="Invalid email or password"
        )


    return render_template(
        "login.html"
    )


# ==========================================
# GOOGLE LOGIN
# ==========================================

@app.route(
    "/login/google"
)
def google_login():

    redirect_uri = url_for(
        "google_callback",
        _external=True
    )

    return google.authorize_redirect(
        redirect_uri
    )


# ==========================================
# GOOGLE CALLBACK
# ==========================================

@app.route(
    "/auth/google/callback"
)
def google_callback():

    try:

        token = google.authorize_access_token()

        user_info = token.get(
            "userinfo"
        )


        if not user_info:

            user_info = google.userinfo()


        email = user_info.get(
            "email"
        )

        name = user_info.get(
            "name"
        )


        if not email:

            return (
                "Google account email "
                "could not be obtained"
            )


        email = email.strip().lower()


        user = User.query.filter_by(
            email=email
        ).first()


        # ==================================
        # CREATE NEW GOOGLE USER
        # ==================================

        if not user:

            user = User(
                name=name or "Google User",
                email=email
            )

            user.set_password(
                os.urandom(24).hex()
            )

            db.session.add(
                user
            )

            db.session.commit()


        login_user(
            user
        )


        # SECURITY PIN IS NOT REQUIRED
        # AFTER GOOGLE LOGIN.
        #
        # User goes directly to dashboard.

        return redirect(
            url_for("dashboard")
        )


    except Exception as error:

        print(
            "Google Login Error:",
            error
        )

        return (
            "Google Login failed. "
            "Check the terminal for details."
        )


# ==========================================
# REGISTER
# ==========================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard")
        )


    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )


        if not name or not email or not password:

            return render_template(
                "register.html",
                error="Please fill all fields."
            )


        if len(password) < 6:

            return render_template(
                "register.html",
                error="Password must contain at least 6 characters."
            )


        existing_user = User.query.filter_by(
            email=email
        ).first()


        if existing_user:

            return render_template(
                "register.html",
                error="Email already registered"
            )


        user = User(
            name=name,
            email=email
        )

        user.set_password(
            password
        )


        db.session.add(
            user
        )

        db.session.commit()


        login_user(
            user
        )


        # SECURITY PIN IS NOT REQUIRED
        # DURING REGISTRATION.
        #
        # User goes directly to dashboard.

        return redirect(
            url_for("dashboard")
        )


    return render_template(
        "register.html"
    )


# ==========================================
# SECURITY PIN SETUP
# ==========================================

@app.route(
    "/pin-setup",
    methods=["GET", "POST"]
)
@login_required
def pin_setup():

    # ======================================
    # PIN ALREADY EXISTS
    # ======================================

    if current_user.security_pin_hash:

        return redirect(
            url_for("dashboard")
        )


    # ======================================
    # CREATE PIN
    # ======================================

    if request.method == "POST":

        pin = request.form.get(
            "pin",
            ""
        ).strip()

        confirm_pin = request.form.get(
            "confirm_pin",
            ""
        ).strip()


        # ==================================
        # VALIDATE PIN
        # ==================================

        if not pin.isdigit():

            return render_template(
                "pin_setup.html",
                error="PIN must contain numbers only."
            )


        if len(pin) != 6:

            return render_template(
                "pin_setup.html",
                error="PIN must contain exactly 6 digits."
            )


        if pin != confirm_pin:

            return render_template(
                "pin_setup.html",
                error="PINs do not match."
            )


        # ==================================
        # EXTRA PROTECTION
        # ==================================
        # Check one more time before saving
        # so an existing PIN is never replaced.

        if current_user.security_pin_hash:

            return redirect(
                url_for("dashboard")
            )


        # ==================================
        # SAVE SECURITY PIN
        # ==================================

        current_user.set_security_pin(
            pin
        )

        db.session.commit()


        # ==================================
        # PIN CREATED SUCCESSFULLY
        # ==================================

        return redirect(
            url_for("dashboard")
        )


    return render_template(
        "pin_setup.html"
    )


# ==========================================
# FORGOT PASSWORD
# ==========================================

@app.route(
    "/forgot-password",
    methods=["GET", "POST"]
)
def forgot_password():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard")
        )


    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()


        user = User.query.filter_by(
            email=email
        ).first()


        if not user:

            return render_template(
                "forgot_password.html",
                error="No account found with this email."
            )


        # ==================================
        # SECURITY PIN REQUIRED FOR RECOVERY
        # ==================================

        if not user.security_pin_hash:

            return render_template(
                "forgot_password.html",
                error=(
                    "Security PIN has not been configured "
                    "for this account. Please log in and "
                    "create your Security PIN first."
                )
            )


        session.pop(
            "reset_user_id",
            None
        )

        session.pop(
            "pin_verified",
            None
        )


        session["reset_user_id"] = user.id


        return redirect(
            url_for(
                "verify_pin"
            )
        )


    return render_template(
        "forgot_password.html"
    )


# ==========================================
# VERIFY SECURITY PIN
# ==========================================

@app.route(
    "/verify-pin",
    methods=["GET", "POST"]
)
def verify_pin():

    user_id = session.get(
        "reset_user_id"
    )


    if not user_id:

        return redirect(
            url_for("forgot_password")
        )


    user = db.session.get(
        User,
        user_id
    )


    if not user:

        session.clear()

        return redirect(
            url_for("forgot_password")
        )


    # ======================================
    # SECURITY PIN MUST EXIST
    # ======================================

    if not user.security_pin_hash:

        session.pop(
            "reset_user_id",
            None
        )

        session.pop(
            "pin_verified",
            None
        )

        return redirect(
            url_for("forgot_password")
        )


    if request.method == "POST":

        pin = request.form.get(
            "pin",
            ""
        ).strip()


        if user.check_security_pin(
            pin
        ):

            session["pin_verified"] = True

            return redirect(
                url_for(
                    "reset_password"
                )
            )


        return render_template(
            "verify_pin.html",
            error="Incorrect recovery PIN."
        )


    return render_template(
        "verify_pin.html"
    )


# ==========================================
# RESET PASSWORD
# ==========================================

@app.route(
    "/reset-password",
    methods=["GET", "POST"]
)
def reset_password():

    user_id = session.get(
        "reset_user_id"
    )

    pin_verified = session.get(
        "pin_verified"
    )


    if not user_id or not pin_verified:

        return redirect(
            url_for("forgot_password")
        )


    user = db.session.get(
        User,
        user_id
    )


    if not user:

        session.clear()

        return redirect(
            url_for("forgot_password")
        )


    if request.method == "POST":

        new_password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        if len(new_password) < 6:

            return render_template(
                "reset_password.html",
                error="Password must contain at least 6 characters."
            )


        if new_password != confirm_password:

            return render_template(
                "reset_password.html",
                error="Passwords do not match."
            )


        user.set_password(
            new_password
        )

        db.session.commit()


        session.pop(
            "reset_user_id",
            None
        )

        session.pop(
            "pin_verified",
            None
        )


        return redirect(
            url_for("login")
        )


    return render_template(
        "reset_password.html"
    )


# ==========================================
# LOGOUT
# ==========================================

@app.route(
    "/logout"
)
@login_required
def logout():

    logout_user()

    return redirect(
        url_for("login")
    )


# ==========================================
# PRIVATE VAULT
# ==========================================

@app.route(
    "/vault",
    methods=["GET", "POST"]
)
@login_required
def vault():

    if request.method == "POST":

        vault_password = request.form.get(
            "vault_password",
            ""
        )


        if not vault_password:

            return render_template(
                "vault.html",
                error="Please enter your Vault password."
            )


        # ==================================
        # FIRST TIME VAULT SETUP
        # ==================================

        if not current_user.vault_password_hash:

            current_user.set_vault_password(
                vault_password
            )

            db.session.commit()


            return redirect(
                url_for("vault_storage")
            )


        # ==================================
        # EXISTING VAULT
        # ==================================

        if current_user.check_vault_password(
            vault_password
        ):

            return redirect(
                url_for("vault_storage")
            )


        return render_template(
            "vault.html",
            error="Incorrect Vault password."
        )


    return render_template(
        "vault.html"
    )


# ==========================================
# VAULT STORAGE
# ==========================================

@app.route(
    "/vault/storage"
)
@login_required
def vault_storage():

    files = VaultFile.query.filter_by(
        user_id=current_user.id
    ).order_by(
        VaultFile.created_at.desc()
    ).all()


    return render_template(
        "vault_storage.html",
        files=files
    )


# ==========================================
# VAULT FILE UPLOAD
# ==========================================

@app.route(
    "/vault/upload",
    methods=["POST"]
)
@login_required
def vault_upload():

    file = request.files.get(
        "file"
    )


    if not file:

        return redirect(
            url_for("vault_storage")
        )


    if file.filename == "":

        return redirect(
            url_for("vault_storage")
        )


    original_filename = secure_filename(
        file.filename
    )


    if not original_filename:

        return redirect(
            url_for("vault_storage")
        )


    file_data = file.read()


    if not file_data:

        return redirect(
            url_for("vault_storage")
        )


    encrypted_data = vault_fernet.encrypt(
        file_data
    )


    stored_filename = (
        str(uuid.uuid4())
        + ".vxvault"
    )


    stored_path = os.path.join(
        app.config["VAULT_FOLDER"],
        stored_filename
    )


    with open(
        stored_path,
        "wb"
    ) as encrypted_file:

        encrypted_file.write(
            encrypted_data
        )


    vault_file = VaultFile(
        user_id=current_user.id,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_type=file.content_type or "unknown",
        file_size=len(file_data)
    )


    db.session.add(
        vault_file
    )

    db.session.commit()


    return redirect(
        url_for("vault_storage")
    )


# ==========================================
# VAULT FILE DOWNLOAD
# ==========================================

@app.route(
    "/vault/download/<int:file_id>"
)
@login_required
def vault_download(file_id):

    vault_file = VaultFile.query.filter_by(
        id=file_id,
        user_id=current_user.id
    ).first_or_404()


    stored_path = os.path.join(
        app.config["VAULT_FOLDER"],
        vault_file.stored_filename
    )


    if not os.path.exists(
        stored_path
    ):

        return "Vault file not found"


    with open(
        stored_path,
        "rb"
    ) as encrypted_file:

        encrypted_data = encrypted_file.read()


    try:

        decrypted_data = vault_fernet.decrypt(
            encrypted_data
        )

    except Exception:

        return (
            "Unable to decrypt this Vault file."
        )


    return send_file(
        io.BytesIO(
            decrypted_data
        ),

        download_name=
            vault_file.original_filename,

        mimetype=
            vault_file.file_type,

        as_attachment=True
    )


# ==========================================
# VAULT FILE DELETE
# ==========================================

@app.route(
    "/vault/delete/<int:file_id>",
    methods=["POST"]
)
@login_required
def vault_delete(file_id):

    vault_file = VaultFile.query.filter_by(
        id=file_id,
        user_id=current_user.id
    ).first_or_404()


    stored_path = os.path.join(
        app.config["VAULT_FOLDER"],
        vault_file.stored_filename
    )


    if os.path.exists(
        stored_path
    ):

        os.remove(
            stored_path
        )


    db.session.delete(
        vault_file
    )

    db.session.commit()


    return redirect(
        url_for("vault_storage")
    )


# ==========================================
# DASHBOARD
# ==========================================

@app.route(
    "/dashboard"
)
@login_required
def dashboard():

    files = os.listdir(
        app.config["UPLOAD_FOLDER"]
    )


    documents = []


    for file in files:

        if file.lower().endswith(
            ".pdf"
        ):

            try:

                result = analyze_file(
                    file
                )

                documents.append(
                    result
                )

            except Exception as error:

                print(
                    "Error analyzing",
                    file,
                    ":",
                    error
                )


    total_documents = len(
        documents
    )


    high_count = sum(
        1
        for doc in documents
        if doc["sensitivity"] == "High"
    )


    medium_count = sum(
        1
        for doc in documents
        if doc["sensitivity"] == "Medium"
    )


    low_count = sum(
        1
        for doc in documents
        if doc["sensitivity"] == "Low"
    )


    category_counts = {}


    for doc in documents:

        category = doc["category"]

        category_counts[category] = (
            category_counts.get(
                category,
                0
            ) + 1
        )


    purpose_counts = {}


    for doc in documents:

        purpose = doc["purpose"]

        purpose_counts[purpose] = (
            purpose_counts.get(
                purpose,
                0
            ) + 1
        )


    return render_template(
        "dashboard.html",

        documents=documents,

        total_documents=
            total_documents,

        high_count=
            high_count,

        medium_count=
            medium_count,

        low_count=
            low_count,

        category_counts=
            category_counts,

        purpose_counts=
            purpose_counts
    )


# ==========================================
# NORMAL PDF UPLOAD
# ==========================================

@app.route(
    "/upload",
    methods=["GET", "POST"]
)
@login_required
def upload():

    if request.method == "POST":

        file = request.files.get(
            "file"
        )


        if file and file.filename != "":

            filename = secure_filename(
                file.filename
            )


            if filename.lower().endswith(
                ".pdf"
            ):

                file_path = os.path.join(
                    app.config["UPLOAD_FOLDER"],
                    filename
                )


                file.save(
                    file_path
                )


        return redirect(
            url_for("dashboard")
        )


    return render_template(
        "upload.html"
    )


# ==========================================
# ANALYZE
# ==========================================

@app.route(
    "/analyze/<filename>"
)
@login_required
def analyze(filename):

    safe_filename = secure_filename(
        filename
    )


    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        safe_filename
    )


    if not os.path.exists(
        file_path
    ):

        return "File not found"


    if not safe_filename.lower().endswith(
        ".pdf"
    ):

        return (
            "Only PDF files can be analyzed"
        )


    result = analyze_file(
        safe_filename
    )


    return render_template(
        "analysis.html",

        filename=
            result["filename"],

        category=
            result["category"],

        sensitivity=
            result["sensitivity"],

        purpose=
            result["purpose"],

        retention=
            result["retention"],

        ai_type=
            result["ai_type"],

        ai_confidence=
            result["ai_confidence"]
    )


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True
    )