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
from datetime import datetime

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

from document_extractor import (
    extract_text,
    get_file_type_label,
    is_analysis_supported
)


# =========================================================
# ENVIRONMENT
# =========================================================

load_dotenv()


# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv(
    "FLASK_SECRET_KEY",
    "visionx-secret-key-change-later"
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///visionx.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Maximum normal upload size = 50 MB
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024


# =========================================================
# NORMAL UPLOAD STORAGE
# =========================================================

UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# =========================================================
# PRIVATE VAULT STORAGE
# =========================================================

VAULT_FOLDER = "vault_storage"

app.config["VAULT_FOLDER"] = VAULT_FOLDER

os.makedirs(
    VAULT_FOLDER,
    exist_ok=True
)


# =========================================================
# VAULT ENCRYPTION
# =========================================================

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


# =========================================================
# DATABASE
# =========================================================

db.init_app(app)


# =========================================================
# LOGIN MANAGER
# =========================================================

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


# =========================================================
# GOOGLE OAUTH
# =========================================================

oauth = OAuth(app)

google = oauth.register(

    name="google",

    client_id=os.getenv(
        "GOOGLE_CLIENT_ID"
    ),

    client_secret=os.getenv(
        "GOOGLE_CLIENT_SECRET"
    ),

    server_metadata_url=(
        "https://accounts.google.com/"
        ".well-known/openid-configuration"
    ),

    client_kwargs={
        "scope": "openid email profile"
    }
)


# =========================================================
# DATABASE INITIALIZATION / REPAIR
# =========================================================

with app.app_context():

    db.create_all()

    # -----------------------------------------------------
    # Repair old VaultFile timestamps
    # -----------------------------------------------------

    old_vault_files = VaultFile.query.filter(
        VaultFile.created_at.is_(None)
    ).all()

    if old_vault_files:

        for vault_file in old_vault_files:

            vault_file.created_at = datetime.utcnow()

        db.session.commit()

        print(
            f"Repaired "
            f"{len(old_vault_files)} old VaultFile "
            f"timestamp(s)."
        )

    # -----------------------------------------------------
    # Ensure security_pin_hash exists
    # -----------------------------------------------------

    inspector = inspect(
        db.engine
    )

    user_columns = [
        column["name"]
        for column in inspector.get_columns(
            "user"
        )
    ]

    if "security_pin_hash" not in user_columns:

        with db.engine.begin() as connection:

            connection.exec_driver_sql(
                """
                ALTER TABLE user
                ADD COLUMN security_pin_hash VARCHAR(255)
                """
            )

        print(
            "Security PIN column added successfully."
        )


# =========================================================
# HELPER — UNIQUE NORMAL UPLOAD NAME
# =========================================================

def make_unique_upload_filename(
    filename
):

    safe_filename = secure_filename(
        filename
    )

    if not safe_filename:

        safe_filename = (
            f"document_{uuid.uuid4().hex}"
        )

    original_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        safe_filename
    )

    if not os.path.exists(
        original_path
    ):

        return safe_filename

    base_name, extension = os.path.splitext(
        safe_filename
    )

    counter = 1

    while True:

        new_filename = (
            f"{base_name}_{counter}"
            f"{extension}"
        )

        new_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            new_filename
        )

        if not os.path.exists(
            new_path
        ):

            return new_filename

        counter += 1


# =========================================================
# HELPER — NORMAL FILE ANALYSIS
# =========================================================

def analyze_file(filename):

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    file_type = get_file_type_label(
        filename
    )

    extraction = extract_text(
        file_path
    )

    # -----------------------------------------------------
    # Unsupported analysis format
    # -----------------------------------------------------

    if not extraction["supported"]:

        return {

            "filename": filename,

            "file_type": file_type,

            "category": "Unavailable",

            "sensitivity": "Unknown",

            "purpose": "Unknown",

            "retention": "Store",

            "ai_type": "Analysis unavailable",

            "ai_confidence": "—",

            "analysis_available": False,

            "extraction_message": extraction[
                "message"
            ],

            "text_available": False
        }

    text = (
        extraction.get("text") or ""
    ).strip()

    # -----------------------------------------------------
    # Supported format but no readable text
    # -----------------------------------------------------

    if not text:

        return {

            "filename": filename,

            "file_type": file_type,

            "category": "General",

            "sensitivity": "Low",

            "purpose": "General",

            "retention": "Review",

            "ai_type": "General Document",

            "ai_confidence": "Low",

            "analysis_available": True,

            "extraction_message": extraction[
                "message"
            ],

            "text_available": False
        }

    # -----------------------------------------------------
    # Existing VisionX intelligence engine
    # -----------------------------------------------------

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

        "file_type": file_type,

        "category": category,

        "sensitivity": sensitivity,

        "purpose": purpose,

        "retention": retention,

        "ai_type": ai_result[
            "document_type"
        ],

        "ai_confidence": ai_result[
            "confidence"
        ],

        "analysis_available": True,

        "extraction_message": extraction[
            "message"
        ],

        "text_available": True
    }


# =========================================================
# LOGIN
# =========================================================

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

            login_user(user)

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


# =========================================================
# GOOGLE LOGIN
# =========================================================

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


@app.route(
    "/auth/google/callback"
)
def google_callback():

    try:

        token = (
            google.authorize_access_token()
        )

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

        if not user:

            user = User(
                name=name or "Google User",
                email=email
            )

            user.set_password(
                os.urandom(24).hex()
            )

            db.session.add(user)

            db.session.commit()

        login_user(user)

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


# =========================================================
# REGISTER
# =========================================================

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
                error=(
                    "Please fill all fields."
                )
            )

        if len(password) < 6:

            return render_template(
                "register.html",
                error=(
                    "Password must contain "
                    "at least 6 characters."
                )
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

        db.session.add(user)

        db.session.commit()

        login_user(user)

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "register.html"
    )


# =========================================================
# SECURITY PIN SETUP
# =========================================================

@app.route(
    "/pin-setup",
    methods=["GET", "POST"]
)
@login_required
def pin_setup():

    # Existing PIN users do not need
    # to create another PIN.

    if current_user.security_pin_hash:

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        pin = request.form.get(
            "pin",
            ""
        ).strip()

        confirm_pin = request.form.get(
            "confirm_pin",
            ""
        ).strip()

        if not pin.isdigit():

            return render_template(
                "pin_setup.html",
                error=(
                    "PIN must contain "
                    "numbers only."
                )
            )

        if len(pin) != 6:

            return render_template(
                "pin_setup.html",
                error=(
                    "PIN must contain "
                    "exactly 6 digits."
                )
            )

        if pin != confirm_pin:

            return render_template(
                "pin_setup.html",
                error="PINs do not match."
            )

        if current_user.security_pin_hash:

            return redirect(
                url_for("dashboard")
            )

        current_user.set_security_pin(
            pin
        )

        db.session.commit()

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "pin_setup.html"
    )


# =========================================================
# FORGOT PASSWORD
# =========================================================

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
                error=(
                    "No account found "
                    "with this email."
                )
            )

        if not user.security_pin_hash:

            return render_template(
                "forgot_password.html",
                error=(
                    "Security PIN is not "
                    "configured for this account."
                )
            )

        session["reset_user_id"] = user.id

        session["pin_verified"] = False

        return redirect(
            url_for("verify_pin")
        )

    return render_template(
        "forgot_password.html"
    )


# =========================================================
# VERIFY SECURITY PIN
# =========================================================

@app.route(
    "/verify-pin",
    methods=["GET", "POST"]
)
def verify_pin():

    reset_user_id = session.get(
        "reset_user_id"
    )

    if not reset_user_id:

        return redirect(
            url_for("forgot_password")
        )

    user = db.session.get(
        User,
        reset_user_id
    )

    if not user:

        session.pop(
            "reset_user_id",
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
                url_for("reset_password")
            )

        return render_template(
            "verify_pin.html",
            error="Incorrect Security PIN."
        )

    return render_template(
        "verify_pin.html"
    )


# =========================================================
# RESET PASSWORD
# =========================================================

@app.route(
    "/reset-password",
    methods=["GET", "POST"]
)
def reset_password():

    reset_user_id = session.get(
        "reset_user_id"
    )

    pin_verified = session.get(
        "pin_verified"
    )

    if not reset_user_id or not pin_verified:

        return redirect(
            url_for("forgot_password")
        )

    user = db.session.get(
        User,
        reset_user_id
    )

    if not user:

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

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if len(password) < 6:

            return render_template(
                "reset_password.html",
                error=(
                    "Password must contain "
                    "at least 6 characters."
                )
            )

        if password != confirm_password:

            return render_template(
                "reset_password.html",
                error="Passwords do not match."
            )

        user.set_password(
            password
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


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/logout"
)
@login_required
def logout():

    logout_user()

    return redirect(
        url_for("login")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route(
    "/dashboard"
)
@login_required
def dashboard():

    files = os.listdir(
        app.config["UPLOAD_FOLDER"]
    )

    documents = []

    for filename in files:

        file_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            filename
        )

        if not os.path.isfile(
            file_path
        ):

            continue

        try:

            result = analyze_file(
                filename
            )

            documents.append(
                result
            )

        except Exception as error:

            print(
                "Error analyzing",
                filename,
                ":",
                error
            )

            documents.append({

                "filename": filename,

                "file_type": get_file_type_label(
                    filename
                ),

                "category": "Unavailable",

                "sensitivity": "Unknown",

                "purpose": "Unknown",

                "retention": "Store",

                "ai_type": "Analysis unavailable",

                "ai_confidence": "—",

                "analysis_available": False,

                "extraction_message": (
                    "This file could not "
                    "be analysed."
                ),

                "text_available": False
            })

    # -----------------------------------------------------
    # Statistics
    # -----------------------------------------------------

    total_documents = len(
        documents
    )

    high_count = sum(
        1
        for document in documents
        if document["sensitivity"] == "High"
    )

    medium_count = sum(
        1
        for document in documents
        if document["sensitivity"] == "Medium"
    )

    low_count = sum(
        1
        for document in documents
        if document["sensitivity"] == "Low"
    )

    # -----------------------------------------------------
    # Category counts
    # -----------------------------------------------------

    category_counts = {}

    for document in documents:

        category = document[
            "category"
        ]

        category_counts[category] = (
            category_counts.get(
                category,
                0
            ) + 1
        )

    # -----------------------------------------------------
    # Purpose counts
    # -----------------------------------------------------

    purpose_counts = {}

    for document in documents:

        purpose = document[
            "purpose"
        ]

        purpose_counts[purpose] = (
            purpose_counts.get(
                purpose,
                0
            ) + 1
        )

    return render_template(

        "dashboard.html",

        documents=documents,

        total_documents=total_documents,

        high_count=high_count,

        medium_count=medium_count,

        low_count=low_count,

        category_counts=category_counts,

        purpose_counts=purpose_counts
    )


# =========================================================
# NORMAL UPLOAD
# =========================================================

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

        if not file:

            return redirect(
                url_for("upload")
            )

        if not file.filename:

            return redirect(
                url_for("upload")
            )

        filename = make_unique_upload_filename(
            file.filename
        )

        file_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            filename
        )

        try:

            file.save(
                file_path
            )

        except Exception as error:

            print(
                "Upload Error:",
                error
            )

            return (
                "File upload failed. "
                "Check the terminal for details."
            )

        # Directly open analysis after upload
        return redirect(
            url_for(
                "analyze",
                filename=filename
            )
        )

    return render_template(
        "upload.html"
    )


# =========================================================
# ANALYZE DOCUMENT
# =========================================================

@app.route(
    "/analyze/<path:filename>"
)
@login_required
def analyze(filename):

    safe_filename = secure_filename(
        filename
    )

    if not safe_filename:

        return "Invalid filename"

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        safe_filename
    )

    if not os.path.exists(
        file_path
    ):

        return "File not found"

    try:

        result = analyze_file(
            safe_filename
        )

    except Exception as error:

        print(
            "Analysis Error:",
            error
        )

        return (
            "Analysis failed. "
            "Check the terminal for details."
        )

    return render_template(

        "analysis.html",

        filename=result[
            "filename"
        ],

        file_type=result[
            "file_type"
        ],

        category=result[
            "category"
        ],

        sensitivity=result[
            "sensitivity"
        ],

        purpose=result[
            "purpose"
        ],

        retention=result[
            "retention"
        ],

        ai_type=result[
            "ai_type"
        ],

        ai_confidence=result[
            "ai_confidence"
        ],

        analysis_available=result[
            "analysis_available"
        ],

        extraction_message=result[
            "extraction_message"
        ],

        text_available=result[
            "text_available"
        ]
    )


# =========================================================
# DELETE NORMAL ANALYSIS FILE
# =========================================================

@app.route(
    "/delete/<path:filename>",
    methods=["POST"]
)
@login_required
def delete_file(filename):

    safe_filename = secure_filename(
        filename
    )

    if not safe_filename:

        return redirect(
            url_for("dashboard")
        )

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        safe_filename
    )

    if os.path.exists(
        file_path
    ):

        try:

            os.remove(
                file_path
            )

        except Exception as error:

            print(
                "Delete Error:",
                error
            )

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# PRIVATE VAULT ENTRY
# =========================================================

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
                error=(
                    "Please enter your "
                    "Vault password."
                )
            )

        # First-time Vault setup
        if not current_user.vault_password_hash:

            current_user.set_vault_password(
                vault_password
            )

            db.session.commit()

            return redirect(
                url_for("vault_storage")
            )

        # Existing Vault
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


# =========================================================
# VAULT STORAGE
# =========================================================

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


# =========================================================
# VAULT UPLOAD
# =========================================================

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

    try:

        file_data = file.read()

    except Exception as error:

        print(
            "Vault read error:",
            error
        )

        return redirect(
            url_for("vault_storage")
        )

    if not file_data:

        return redirect(
            url_for("vault_storage")
        )

    # -----------------------------------------------------
    # Encrypt before storing
    # -----------------------------------------------------

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

    try:

        with open(
            stored_path,
            "wb"
        ) as encrypted_file:

            encrypted_file.write(
                encrypted_data
            )

    except Exception as error:

        print(
            "Vault storage error:",
            error
        )

        return redirect(
            url_for("vault_storage")
        )

    # -----------------------------------------------------
    # Database record
    # -----------------------------------------------------

    vault_file = VaultFile(

        user_id=current_user.id,

        original_filename=original_filename,

        stored_filename=stored_filename,

        file_type=(
            file.content_type
            or "unknown"
        ),

        file_size=len(
            file_data
        ),

        created_at=datetime.utcnow()
    )

    db.session.add(
        vault_file
    )

    db.session.commit()

    return redirect(
        url_for("vault_storage")
    )


# =========================================================
# VAULT DOWNLOAD / DECRYPT
# =========================================================

@app.route(
    "/vault/download/<int:file_id>"
)
@login_required
def vault_download(file_id):

    vault_file = VaultFile.query.filter_by(
        id=file_id,
        user_id=current_user.id
    ).first()

    if not vault_file:

        return "Vault file not found", 404

    stored_path = os.path.join(
        app.config["VAULT_FOLDER"],
        vault_file.stored_filename
    )

    if not os.path.exists(
        stored_path
    ):

        return "Encrypted file not found", 404

    try:

        with open(
            stored_path,
            "rb"
        ) as encrypted_file:

            encrypted_data = (
                encrypted_file.read()
            )

        decrypted_data = (
            vault_fernet.decrypt(
                encrypted_data
            )
        )

    except Exception as error:

        print(
            "Vault decrypt error:",
            error
        )

        return (
            "Could not decrypt this file.",
            500
        )

    return send_file(

        io.BytesIO(
            decrypted_data
        ),

        as_attachment=True,

        download_name=(
            vault_file.original_filename
        ),

        mimetype=(
            vault_file.file_type
            or "application/octet-stream"
        )
    )


# =========================================================
# VAULT DELETE
# =========================================================

@app.route(
    "/vault/delete/<int:file_id>",
    methods=["POST"]
)
@login_required
def vault_delete(file_id):

    vault_file = VaultFile.query.filter_by(
        id=file_id,
        user_id=current_user.id
    ).first()

    if not vault_file:

        return redirect(
            url_for("vault_storage")
        )

    stored_path = os.path.join(
        app.config["VAULT_FOLDER"],
        vault_file.stored_filename
    )

    # Delete encrypted physical file
    if os.path.exists(
        stored_path
    ):

        try:

            os.remove(
                stored_path
            )

        except Exception as error:

            print(
                "Vault delete error:",
                error
            )

    # Delete database record
    db.session.delete(
        vault_file
    )

    db.session.commit()

    return redirect(
        url_for("vault_storage")
    )


# =========================================================
# FILE SIZE ERROR
# =========================================================

@app.errorhandler(
    413
)
def request_entity_too_large(error):

    return (
        "File is too large. "
        "VisionX allows files up to 50 MB.",
        413
    )


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )