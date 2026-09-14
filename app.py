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

from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    logout_user,
    current_user
)

from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from sqlalchemy import inspect

from models import db, User, VaultFile

from document_extractor import (
    extract_text,
    get_file_type_label,
    is_analysis_supported
)

from intelligence import generate_intelligence


# =========================================================
# LOAD ENVIRONMENT
# =========================================================

load_dotenv()


# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__)


# =========================================================
# APP CONFIGURATION
# =========================================================

app.config["SECRET_KEY"] = "visionx-secret-key-change-later"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///visionx.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Maximum upload size = 50 MB
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024


# =========================================================
# NORMAL DOCUMENT STORAGE
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
# VAULT ENCRYPTION KEY
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

    inspector = inspect(
        db.engine
    )

    # -----------------------------------------
    # SECURITY PIN MIGRATION
    # -----------------------------------------

    user_columns = [
        column["name"]
        for column in inspector.get_columns("user")
    ]

    if "security_pin_hash" not in user_columns:

        with db.engine.begin() as connection:

            connection.exec_driver_sql(
                "ALTER TABLE user "
                "ADD COLUMN security_pin_hash VARCHAR(255)"
            )

        print(
            "Security PIN column added successfully."
        )

    # -----------------------------------------
    # VAULT CREATED_AT REPAIR
    # -----------------------------------------

    try:

        with db.engine.begin() as connection:

            connection.exec_driver_sql(
                "UPDATE vault_file "
                "SET created_at = CURRENT_TIMESTAMP "
                "WHERE created_at IS NULL"
            )

    except Exception as error:

        print(
            "Vault timestamp repair skipped:",
            error
        )


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def make_unique_upload_filename(filename):

    """
    Prevent filename collisions.

    Example:
        resume.pdf
        resume_1.pdf
        resume_2.pdf
    """

    safe_name = secure_filename(
        filename
    )

    if not safe_name:

        return None

    base, extension = os.path.splitext(
        safe_name
    )

    candidate = safe_name

    counter = 1

    while os.path.exists(
        os.path.join(
            app.config["UPLOAD_FOLDER"],
            candidate
        )
    ):

        candidate = (
            f"{base}_{counter}{extension}"
        )

        counter += 1

    return candidate


def get_analysis_result(filename):

    """
    Extract text from a file and run
    VisionX Intelligence V2.
    """

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    if not os.path.exists(file_path):

        return {
            "filename": filename,
            "supported": False,
            "file_type": get_file_type_label(filename),
            "message": "File not found.",
            "text": "",
            "document_type": "Unavailable",
            "confidence": 0,
            "confidence_label": "Unavailable",
            "risk_flags": [],
            "risk_count": 0,
            "key_information": [],
            "recommended_action": "Review",
            "summary": "The requested file could not be found."
        }

    file_type = get_file_type_label(
        filename
    )

    supported = is_analysis_supported(
        filename
    )

    extraction = extract_text(
        file_path
    )

    if not extraction.get("supported"):

        return {
            "filename": filename,
            "supported": False,
            "file_type": file_type,
            "message": extraction.get(
                "message",
                "Analysis is unavailable for this file type."
            ),
            "text": "",
            "document_type": "Unavailable",
            "confidence": 0,
            "confidence_label": "Unavailable",
            "risk_flags": [],
            "risk_count": 0,
            "key_information": [],
            "recommended_action": "Store securely",
            "summary": (
                "This file can be stored in VisionX, "
                "but automatic analysis is unavailable "
                "for this format."
            )
        }

    if not supported:

        return {
            "filename": filename,
            "supported": False,
            "file_type": file_type,
            "message": (
                "Analysis is unavailable for this "
                "file type."
            ),
            "text": "",
            "document_type": "Unavailable",
            "confidence": 0,
            "confidence_label": "Unavailable",
            "risk_flags": [],
            "risk_count": 0,
            "key_information": [],
            "recommended_action": "Store securely",
            "summary": (
                "This file format is not currently "
                "supported by the VisionX analysis engine."
            )
        }

    text = extraction.get(
        "text",
        ""
    )

    if not text.strip():

        return {
            "filename": filename,
            "supported": True,
            "file_type": file_type,
            "message": extraction.get(
                "message",
                "No readable text was extracted."
            ),
            "text": "",
            "document_type": "Unreadable Document",
            "confidence": 0,
            "confidence_label": "Low",
            "risk_flags": [],
            "risk_count": 0,
            "key_information": [],
            "recommended_action": "Review",
            "summary": (
                "VisionX could not extract enough "
                "readable text to perform intelligent analysis."
            )
        }

    intelligence = generate_intelligence(
        text
    )

    return {
        "filename": filename,
        "supported": True,
        "file_type": file_type,
        "message": extraction.get(
            "message",
            "Text extracted successfully."
        ),
        "text": text,

        "document_type": intelligence.get(
            "document_type",
            "General Document"
        ),

        "confidence": intelligence.get(
            "confidence",
            0
        ),

        "confidence_label": intelligence.get(
            "confidence_label",
            "Medium"
        ),

        "risk_flags": intelligence.get(
            "risk_flags",
            []
        ),

        "risk_count": intelligence.get(
            "risk_count",
            0
        ),

        "key_information": intelligence.get(
            "key_information",
            []
        ),

        "recommended_action": intelligence.get(
            "recommended_action",
            "Review"
        ),

        "summary": intelligence.get(
            "summary",
            "No intelligence summary available."
        )
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

            login_user(
                user
            )

            # Security PIN is requested
            # only once during normal login.
            if not user.security_pin_hash:

                return redirect(
                    url_for("pin_setup")
                )

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


# =========================================================
# GOOGLE CALLBACK
# =========================================================

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

        # -----------------------------------------
        # CREATE GOOGLE USER
        # -----------------------------------------

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

        if not user.security_pin_hash:

            return redirect(
                url_for("pin_setup")
            )

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
                error="Please fill all fields."
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

        db.session.add(
            user
        )

        db.session.commit()

        login_user(
            user
        )

        return redirect(
            url_for("pin_setup")
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
                    "No account found with this email."
                )
            )

        if not user.security_pin_hash:

            return render_template(
                "forgot_password.html",
                error=(
                    "Recovery PIN has not been "
                    "configured for this account."
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
            url_for("verify_pin")
        )

    return render_template(
        "forgot_password.html"
    )


# =========================================================
# VERIFY RECOVERY PIN
# =========================================================

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
                url_for("reset_password")
            )

        return render_template(
            "verify_pin.html",
            error="Incorrect recovery PIN."
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
                error=(
                    "Password must contain "
                    "at least 6 characters."
                )
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
# PRIVATE VAULT LOGIN
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
                    "Please enter your Vault password."
                )
            )

        # -----------------------------------------
        # FIRST VAULT SETUP
        # -----------------------------------------

        if not current_user.vault_password_hash:

            current_user.set_vault_password(
                vault_password
            )

            db.session.commit()

            return redirect(
                url_for("vault_storage")
            )

        # -----------------------------------------
        # EXISTING VAULT
        # -----------------------------------------

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
# VAULT FILE UPLOAD
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

        file_type=(
            file.content_type
            or "unknown"
        ),

        file_size=len(file_data)
    )

    db.session.add(
        vault_file
    )

    db.session.commit()

    return redirect(
        url_for("vault_storage")
    )


# =========================================================
# VAULT FILE DOWNLOAD
# =========================================================

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

        download_name=(
            vault_file.original_filename
        ),

        mimetype=(
            vault_file.file_type
        ),

        as_attachment=True
    )


# =========================================================
# VAULT FILE DELETE
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

            result = get_analysis_result(
                filename
            )

            documents.append(
                result
            )

        except Exception as error:

            print(
                "Dashboard analysis error:",
                filename,
                error
            )

            documents.append({

                "filename": filename,

                "supported": False,

                "file_type": get_file_type_label(
                    filename
                ),

                "message": (
                    "Automatic analysis failed."
                ),

                "text": "",

                "document_type": "Unavailable",

                "confidence": 0,

                "confidence_label": "Unavailable",

                "risk_flags": [],

                "risk_count": 0,

                "key_information": [],

                "recommended_action": "Review",

                "summary": (
                    "VisionX could not analyze "
                    "this file automatically."
                )
            })

    # =====================================================
    # DASHBOARD STATISTICS
    # =====================================================

    total_documents = len(
        documents
    )

    high_count = sum(

        1

        for doc in documents

        if any(
            flag.get("level") == "High"
            for flag in doc.get(
                "risk_flags",
                []
            )
            if isinstance(flag, dict)
        )
    )

    medium_count = sum(

        1

        for doc in documents

        if any(
            flag.get("level") == "Medium"
            for flag in doc.get(
                "risk_flags",
                []
            )
            if isinstance(flag, dict)
        )
    )

    low_count = max(
        total_documents
        - high_count
        - medium_count,
        0
    )

    category_counts = {}

    purpose_counts = {}

    document_type_counts = {}

    for doc in documents:

        document_type = doc.get(
            "document_type",
            "General Document"
        )

        document_type_counts[
            document_type
        ] = (
            document_type_counts.get(
                document_type,
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

        purpose_counts=purpose_counts,

        document_type_counts=document_type_counts
    )


# =========================================================
# NORMAL MULTI-FORMAT UPLOAD
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

        if not file or file.filename == "":

            return redirect(
                url_for("upload")
            )

        filename = make_unique_upload_filename(
            file.filename
        )

        if not filename:

            return redirect(
                url_for("upload")
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
                "Upload error:",
                error
            )

            return redirect(
                url_for("upload")
            )

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

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        safe_filename
    )

    if not os.path.exists(
        file_path
    ):

        return "File not found", 404

    result = get_analysis_result(
        safe_filename
    )

    return render_template(

        "analysis.html",

        filename=result["filename"],

        file_type=result["file_type"],

        supported=result["supported"],

        extraction_message=result["message"],

        document_type=result["document_type"],

        confidence=result["confidence"],

        confidence_label=result["confidence_label"],

        risk_flags=result["risk_flags"],

        risk_count=result["risk_count"],

        key_information=result["key_information"],

        recommended_action=result["recommended_action"],

        summary=result["summary"]
    )


# =========================================================
# DELETE NORMAL DOCUMENT
# =========================================================

@app.route(
    "/delete/<path:filename>",
    methods=["POST", "GET"]
)
@login_required
def delete_file(filename):

    safe_filename = secure_filename(
        filename
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
                "Delete error:",
                error
            )

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# 413 — FILE TOO LARGE
# =========================================================

@app.errorhandler(413)
def request_entity_too_large(error):

    return render_template(
        "upload.html",
        error=(
            "File is too large. "
            "Maximum allowed size is 50 MB."
        )
    ), 413


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )