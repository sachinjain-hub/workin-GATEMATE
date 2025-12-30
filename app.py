import os
import random
import io
import base64
from uuid import uuid4
from datetime import datetime, timedelta, timezone

from flask import (
    Flask, render_template, redirect,
    url_for, flash, request, session
)

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import bcrypt
import qrcode
from twilio.rest import Client
tables_created = False

# =====================================================
# APP CONFIG
# =====================================================
app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True

# =====================================================
# DATABASE CONFIG
# =====================================================

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# =====================================================
# TWILIO CONFIG
# =====================================================
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER")

twilio_client = None
if all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER]):
    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
else:
    print("⚠️ Twilio disabled")

# =====================================================
# DATABASE MODELS
# =====================================================
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    parents_phone = db.Column(db.String(20))
    role = db.Column(db.String(20), default="student")

    # 🔥 NEW (FOR ROUTING)
    branch = db.Column(db.String(50))
    year = db.Column(db.String(10))


class GatePassRequest(db.Model):
    __tablename__ = "gate_pass_requests"

    id = db.Column(db.Integer, primary_key=True)

    student_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # 🔥 NEW (HOD ROUTING)
    hod_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    student_name = db.Column(db.String(120))
    reason = db.Column(db.Text)
    out_date = db.Column(db.String(20))
    out_time = db.Column(db.String(20))
    status = db.Column(db.String(20), default="Pending")

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    qr_token = db.Column(db.String(100), unique=True)
    qr_expires_at = db.Column(db.DateTime)
    qr_used = db.Column(db.Boolean, default=False)
@app.before_request
def create_tables_once():
    global tables_created
    if not tables_created:
        with app.app_context():
            db.create_all()
            tables_created = True

# =====================================================
# HELPERS
# =====================================================
def format_phone(phone):
    phone = phone.strip()
    if phone.startswith("0"):
        phone = phone[1:]
    if not phone.startswith("+"):
        phone = "+91" + phone
    return phone


def send_sms(phone, message):
    if not twilio_client:
        return
    try:
        twilio_client.messages.create(
            body=message,
            from_=TWILIO_FROM_NUMBER,
            to=phone
        )
    except Exception as e:
        print("Twilio error:", e)


def generate_qr_code(data):
    qr = qrcode.QRCode(box_size=8, border=3)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

# =====================================================
# ROUTES
# =====================================================


@app.route("/")
def index():
    return render_template("index.html")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if user and bcrypt.checkpw(
            request.form["password"].encode(),
            user.password.encode()
        ):
            session.permanent = True
            session["user_id"] = user.id
            session["role"] = user.role
            session["name"] = user.name
            return redirect(url_for("hod_dashboard") if user.role == "hod" else url_for("student"))

        flash("Invalid credentials", "danger")

    return render_template("login.html")


# ================= STUDENT =================
@app.route("/student", methods=["GET", "POST"])
def student():
    if session.get("role") != "student":
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    # ================= OTP VERIFY =================
    if request.method == "POST" and session.get("otp_phase"):
        if datetime.now(timezone.utc) > session.get("otp_expiry"):
            flash("OTP expired", "danger")
            session.clear()
            return redirect(url_for("student"))

        if request.form.get("otp") != str(session.get("otp")):
            flash("Invalid OTP", "danger")
            return redirect(url_for("student"))

        hod = User.query.filter_by(
            role="hod",
            branch=user.branch,
            year=user.year
        ).first()

        if not hod:
            flash("No HOD found for your branch & year", "danger")
            return redirect(url_for("student"))

        req = GatePassRequest(
            student_id=user.id,
            hod_id=hod.id,
            student_name=user.name,
            **session["pending"]
        )

        db.session.add(req)
        db.session.commit()

        session.clear()
        flash("Gate pass submitted successfully", "success")
        return redirect(url_for("student"))

    # ================= SEND OTP =================
    if request.method == "POST":
        otp = random.randint(100000, 999999)

        session["otp"] = otp
        session["otp_phase"] = True
        session["otp_expiry"] = datetime.now(timezone.utc) + timedelta(minutes=5)
        session["pending"] = {
            "reason": request.form["reason"],
            "out_date": request.form["out_date"],
            "out_time": request.form["out_time"]
        }

        send_sms(user.parents_phone, f"OTP for gate pass is {otp}")
        flash("OTP sent to parent's mobile", "info")
        return redirect(url_for("student"))

    # ================= FETCH REQUESTS =================
    gate_requests = (
        GatePassRequest.query
        .filter_by(student_id=user.id)
        .order_by(GatePassRequest.created_at.desc())
        .all()
    )

    now = datetime.now(timezone.utc)
    requests_list = []

    for r in gate_requests:
        qr_code_data = None
        expires_at = r.qr_expires_at

        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if (
            expires_at
            and expires_at > now
            and r.status == "Approved"
            and not r.qr_used
        ):
            verify_url = url_for("verify_qr", token=r.qr_token, _external=True)
            qr_code_data = generate_qr_code(verify_url)

        requests_list.append({
            "id": r.id,
            "reason": r.reason,
            "out_date": r.out_date,
            "out_time": r.out_time,
            "status": r.status,
            "created_at": r.created_at,
            "qr_code_data": qr_code_data,
            "qr_expires_at": expires_at
        })

    return render_template(
        "student.html",
        student_name=user.name,
        requests_list=requests_list,
        otp_required=session.get("otp_phase", False)
    )



# ================= HOD =================
@app.route("/hod")
def hod_dashboard():
    if session.get("role") != "hod":
        return redirect(url_for("login"))

    requests = GatePassRequest.query.filter_by(
        hod_id=session["user_id"]
    ).order_by(GatePassRequest.created_at.desc()).all()

    return render_template("hod.html", requests=requests)


@app.route("/hod/update/<int:id>", methods=["POST"])
def update_request(id):
    if session.get("role") != "hod":
        return redirect(url_for("login"))

    req = GatePassRequest.query.get_or_404(id)
    student = User.query.get(req.student_id)

    action = request.form.get("action")

    if action == "Approved":
        req.status = "Approved"
        req.qr_token = uuid4().hex
        req.qr_expires_at = datetime.now(timezone.utc) + timedelta(minutes=20)
        req.qr_used = False

        if student:
            send_sms(
                student.parents_phone,
                f"Gate pass of {student.name} has been APPROVED"
            )

    elif action == "Rejected":
        req.status = "Rejected"

    db.session.commit()
    return redirect(url_for("hod_dashboard"))


@app.route("/verify-qr/<token>")
def verify_qr(token):
    try:
        req = GatePassRequest.query.filter_by(qr_token=token).first()

        # ❌ Invalid token
        if not req:
            return render_template("qr_result.html", status="invalid")

        # ⚠️ Already used
        if req.qr_used:
            return render_template("qr_result.html", status="used")

        # ❌ Missing expiry
        if not req.qr_expires_at:
            return render_template("qr_result.html", status="expired")

        expires_at = req.qr_expires_at

        # 🔥 Fix timezone issue
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        # ⛔ Expired
        if now > expires_at:
            return render_template("qr_result.html", status="expired")

        # ✅ VALID QR
        req.qr_used = True
        db.session.commit()

        return render_template("qr_result.html", status="valid")

    except Exception as e:
        print("❌ QR VERIFY ERROR:", e)
        return "Internal Server Error", 500



@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =====================================================
# MAIN
# =====================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

