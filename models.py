from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


db = SQLAlchemy()


class User(UserMixin, db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=True
    )

    vault_password_hash = db.Column(
        db.String(255),
        nullable=True
    )

    # ==========================================
    # SECURITY PIN
    # ==========================================

    security_pin_hash = db.Column(
        db.String(255),
        nullable=True
    )

    # ==========================================
    # NORMAL PASSWORD
    # ==========================================

    def set_password(self, password):

        self.password_hash = generate_password_hash(
            password
        )

    def check_password(self, password):

        if not self.password_hash:
            return False

        return check_password_hash(
            self.password_hash,
            password
        )

    # ==========================================
    # SECURITY PIN
    # ==========================================

    def set_security_pin(self, pin):

        self.security_pin_hash = generate_password_hash(
            pin
        )

    def check_security_pin(self, pin):

        if not self.security_pin_hash:
            return False

        return check_password_hash(
            self.security_pin_hash,
            pin
        )

    # ==========================================
    # VAULT PASSWORD
    # ==========================================

    def set_vault_password(self, password):

        self.vault_password_hash = generate_password_hash(
            password
        )

    def check_vault_password(self, password):

        if not self.vault_password_hash:
            return False

        return check_password_hash(
            self.vault_password_hash,
            password
        )


# ==========================================
# VAULT FILE
# ==========================================

class VaultFile(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    original_filename = db.Column(
        db.String(255),
        nullable=False
    )

    stored_filename = db.Column(
        db.String(255),
        nullable=False
    )

    file_type = db.Column(
        db.String(50),
        nullable=False
    )

    file_size = db.Column(
        db.Integer,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )