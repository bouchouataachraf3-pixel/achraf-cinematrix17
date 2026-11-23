"""
CINEMATRIX - Application Flask avec authentification complète.

Fonctionnalités :
  - Inscription (nom d'utilisateur, email, mot de passe)
  - Connexion (par nom d'utilisateur OU email)
  - Mot de passe oublié -> lien de réinitialisation (valable 1 h, usage unique)
  - Page de réinitialisation du mot de passe
  - Accueil, Contact, À propos, Profil (barre de navigation)
"""
from __future__ import annotations

import math
import os
import re
import secrets
import smtplib
import sqlite3
import time
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

from flask import (
    Flask, abort, flash, g, redirect, render_template, request, session, url_for,
)
from markupsafe import Markup
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
SECRET_FILE = os.path.join(BASE_DIR, ".secret_key")

RESET_TOKEN_MAX_AGE = 3600  # 1 heure
MAX_FAILED_LOGINS = 5       # tentatives échouées autorisées...
LOCKOUT_SECONDS = 600       # ...par fenêtre de 10 minutes
_failed_logins: dict[str, list[float]] = {}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")


def load_secret_key() -> str:
    """Clé secrète : variable d'environnement, sinon fichier généré une fois."""
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    if not os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "w") as f:
            f.write(secrets.token_hex(32))
    with open(SECRET_FILE) as f:
        return f.read().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),  # "Se souvenir de moi"
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,             # taille max d'un envoi : 4 Mo
)
AVATAR_DIR = os.path.join(BASE_DIR, "static", "uploads", "avatars")
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


# --------------------------------------------------------------------------
# Base de données (SQLite)
# --------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            bio TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS calculations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            mass REAL NOT NULL,          -- masse m (g)
            molar_mass REAL NOT NULL,    -- masse molaire M (g/mol)
            moles REAL NOT NULL,         -- n = m / M (mol)
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_calc_user ON calculations(user_id, id);
        """
    )
    cols = [r[1] for r in db.execute("PRAGMA table_info(users)")]
    if "avatar" not in cols:  # migration pour les anciennes bases
        db.execute("ALTER TABLE users ADD COLUMN avatar TEXT NOT NULL DEFAULT ''")
    if "is_admin" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
    mcols = [r[1] for r in db.execute("PRAGMA table_info(messages)")]
    if "is_read" not in mcols:
        db.execute("ALTER TABLE messages ADD COLUMN is_read INTEGER NOT NULL DEFAULT 0")
    # Anciennes bases : s'il n'y a aucun admin, le plus ancien compte le devient
    if not db.execute("SELECT 1 FROM users WHERE is_admin = 1").fetchone():
        db.execute("UPDATE users SET is_admin = 1 WHERE id = (SELECT MIN(id) FROM users)")
    db.commit()
    db.close()


# --------------------------------------------------------------------------
# Sécurité : CSRF + utilisateur courant
# --------------------------------------------------------------------------
def csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_and_load_user():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
            abort(400, "Jeton CSRF invalide. Rechargez la page et réessayez.")
    g.user = None
    uid = session.get("user_id")
    if uid is not None:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if g.user is None:
            session.clear()


@app.context_processor
def inject_user():
    user = g.get("user")
    unread = 0
    if user is not None and user["is_admin"]:
        unread = get_db().execute("SELECT COUNT(*) FROM messages WHERE is_read = 0").fetchone()[0]
    return {"current_user": user, "year": datetime.now().year, "unread_count": unread}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Veuillez vous connecter pour accéder à cette page.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not g.user["is_admin"]:
            abort(403, "Accès réservé à l'administrateur.")
        return view(*args, **kwargs)

    return wrapped


def safe_next(target: str | None) -> str | None:
    """N'autorise que les redirections internes."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return None


def _attempt_key(identifier: str) -> str:
    return f"{request.remote_addr}|{identifier.lower()}"


def is_locked_out(identifier: str) -> int:
    """Retourne le nombre de secondes restantes de blocage (0 si non bloqué)."""
    now = time.time()
    recent = [t for t in _failed_logins.get(_attempt_key(identifier), []) if now - t < LOCKOUT_SECONDS]
    _failed_logins[_attempt_key(identifier)] = recent
    if len(recent) >= MAX_FAILED_LOGINS:
        return int(LOCKOUT_SECONDS - (now - recent[0]))
    return 0


def detect_image_ext(data: bytes) -> str | None:
    """Détecte le vrai type de l'image (pas seulement l'extension du nom)."""
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def remove_avatar_file(filename: str):
    if filename:
        try:
            os.remove(os.path.join(AVATAR_DIR, os.path.basename(filename)))
        except OSError:
            pass


NUM_RE = re.compile(r"[0-9]{1,15}(?:[.,][0-9]{1,15})?")  # chiffres uniquement, virgule ou point


def parse_positive_number(raw: str) -> float | None:
    """Convertit '18,015' en 18.015. Retourne None si la saisie n'est pas un
    nombre strictement positif (lettres, symboles, vide, 0, négatif...)."""
    raw = raw.strip()
    if not NUM_RE.fullmatch(raw):
        return None
    value = float(raw.replace(",", "."))
    return value if value > 0 and math.isfinite(value) else None


@app.template_filter("num")
def fmt_num(x) -> str:
    """6 chiffres significatifs ; notation scientifique pour les très grands/petits."""
    text = f"{x:.6g}"
    if "e" in text:
        mantissa, exp = text.split("e")
        return Markup(f"{mantissa} × 10<sup>{int(exp)}</sup>")
    return text


def validate_password(pwd: str, confirm: str) -> list[str]:
    errors = []
    if len(pwd) < 8:
        errors.append("Le mot de passe doit contenir au moins 8 caractères.")
    if not re.search(r"[A-Za-z]", pwd) or not re.search(r"\d", pwd):
        errors.append("Le mot de passe doit contenir des lettres et des chiffres.")
    if pwd != confirm:
        errors.append("Les mots de passe ne correspondent pas.")
    return errors


# --------------------------------------------------------------------------
# Envoi d'email (SMTP optionnel)
# --------------------------------------------------------------------------
def send_reset_email(to_email: str, username: str, link: str) -> bool:
    """Envoie l'email via SMTP si configuré. Retourne True si envoyé."""
    host = os.environ.get("SMTP_HOST")
    if not host:
        return False
    msg = EmailMessage()
    msg["Subject"] = "CINEMATRIX - Réinitialisation du mot de passe"
    msg["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", "no-reply@cinematrix.local"))
    msg["To"] = to_email
    msg.set_content(
        f"Bonjour {username},\n\n"
        f"Pour choisir un nouveau mot de passe, ouvrez ce lien (valable 1 heure) :\n{link}\n\n"
        "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email."
    )
    try:
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587)), timeout=10) as s:
            s.starttls()
            if os.environ.get("SMTP_USER"):
                s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
            s.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001
        app.logger.error("Échec d'envoi d'email : %s", exc)
        return False


def make_reset_token(user) -> str:
    # Le fragment du hash rend le jeton à usage unique : il devient invalide
    # dès que le mot de passe change.
    return serializer.dumps(
        {"id": user["id"], "h": user["password_hash"][-12:]}, salt="password-reset"
    )


def read_reset_token(token: str):
    try:
        data = serializer.loads(token, salt="password-reset", max_age=RESET_TOKEN_MAX_AGE)
    except (SignatureExpired, BadSignature):
        return None
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (data.get("id"),)).fetchone()
    if user is None or user["password_hash"][-12:] != data.get("h"):
        return None
    return user


# --------------------------------------------------------------------------
# Authentification
# --------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("home"))
    form = {"username": "", "email": ""}
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        pwd = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        form.update(username=username, email=email)

        errors = []
        if not USERNAME_RE.match(username):
            errors.append("Nom d'utilisateur : 3 à 30 caractères (lettres, chiffres, _ . -).")
        if not EMAIL_RE.match(email):
            errors.append("Adresse email invalide.")
        errors += validate_password(pwd, confirm)

        db = get_db()
        if not errors:
            if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                errors.append("Ce nom d'utilisateur est déjà pris.")
            if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
                errors.append("Cette adresse email est déjà utilisée.")

        if errors:
            for e in errors:
                flash(e, "error")
        else:
            is_first = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
            db.execute(
                "INSERT INTO users (username, email, password_hash, created_at, is_admin) VALUES (?,?,?,?,?)",
                (username, email, generate_password_hash(pwd),
                 datetime.now().isoformat(timespec="seconds"), 1 if is_first else 0),
            )
            db.commit()
            flash("Compte créé avec succès. Vous pouvez vous connecter.", "success")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("home"))
    identifier = ""
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        pwd = request.form.get("password", "")
        wait = is_locked_out(identifier)
        if wait:
            flash(f"Trop de tentatives. Réessayez dans {wait // 60 + 1} minute(s).", "error")
            return render_template("login.html", identifier=identifier), 429
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier, identifier.lower()),
        ).fetchone()
        if user and check_password_hash(user["password_hash"], pwd):
            _failed_logins.pop(_attempt_key(identifier), None)
            session.clear()
            session["user_id"] = user["id"]
            if request.form.get("remember"):
                session.permanent = True
            flash(f"Bienvenue, {user['username']} !", "success")
            return redirect(safe_next(request.args.get("next")) or url_for("home"))
        _failed_logins.setdefault(_attempt_key(identifier), []).append(time.time())
        flash("Identifiants incorrects.", "error")
    return render_template("login.html", identifier=identifier)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Vous êtes déconnecté. À bientôt !", "success")
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    dev_link = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not EMAIL_RE.match(email):
            flash("Adresse email invalide.", "error")
        else:
            user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user:
                link = url_for("reset_password", token=make_reset_token(user), _external=True)
                if not send_reset_email(user["email"], user["username"], link):
                    # Mode développement : pas de SMTP configuré
                    app.logger.warning("LIEN DE RÉINITIALISATION (%s) : %s", email, link)
                    dev_link = link
            # Même message dans tous les cas : ne révèle pas si l'email existe
            flash(
                "Si un compte existe avec cette adresse, un lien de réinitialisation a été envoyé.",
                "success",
            )
    return render_template("forgot_password.html", dev_link=dev_link)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = read_reset_token(token)
    if user is None:
        flash("Ce lien est invalide ou a expiré. Faites une nouvelle demande.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        errors = validate_password(request.form.get("password", ""), request.form.get("confirm", ""))
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            db = get_db()
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(request.form["password"]), user["id"]),
            )
            db.commit()
            flash("Mot de passe réinitialisé. Connectez-vous avec le nouveau.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)


# --------------------------------------------------------------------------
# Pages principales
# --------------------------------------------------------------------------
@app.route("/")
@login_required
def home():
    return render_template("index.html")


@app.route("/about")
@login_required
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
@login_required
def contact():
    form = {"name": g.user["username"], "email": g.user["email"], "subject": "", "body": ""}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("name", "email", "subject", "body")}
        if not all(form.values()):
            flash("Tous les champs sont obligatoires.", "error")
        elif not EMAIL_RE.match(form["email"]):
            flash("Adresse email invalide.", "error")
        elif len(form["body"]) > 3000:
            flash("Message trop long (3000 caractères max).", "error")
        else:
            db = get_db()
            db.execute(
                "INSERT INTO messages (name,email,subject,body,created_at) VALUES (?,?,?,?,?)",
                (*[form[k] for k in ("name", "email", "subject", "body")],
                 datetime.now().isoformat(timespec="seconds")),
            )
            db.commit()
            flash("Message envoyé. Nous vous répondrons rapidement.", "success")
            return redirect(url_for("contact"))
    return render_template("contact.html", form=form)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    action = request.form.get("action")
    if request.method == "POST" and action == "info":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        bio = request.form.get("bio", "").strip()[:300]
        errors = []
        if not USERNAME_RE.match(username):
            errors.append("Nom d'utilisateur : 3 à 30 caractères (lettres, chiffres, _ . -).")
        if not EMAIL_RE.match(email):
            errors.append("Adresse email invalide.")
        if not errors:
            if db.execute("SELECT 1 FROM users WHERE username=? AND id<>?", (username, g.user["id"])).fetchone():
                errors.append("Ce nom d'utilisateur est déjà pris.")
            if db.execute("SELECT 1 FROM users WHERE email=? AND id<>?", (email, g.user["id"])).fetchone():
                errors.append("Cette adresse email est déjà utilisée.")
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            db.execute("UPDATE users SET username=?, email=?, bio=? WHERE id=?",
                       (username, email, bio, g.user["id"]))
            db.commit()
            flash("Profil mis à jour.", "success")
        return redirect(url_for("profile"))

    if request.method == "POST" and action == "password":
        if not check_password_hash(g.user["password_hash"], request.form.get("current", "")):
            flash("Mot de passe actuel incorrect.", "error")
        else:
            errors = validate_password(request.form.get("password", ""), request.form.get("confirm", ""))
            if errors:
                for e in errors:
                    flash(e, "error")
            else:
                db.execute("UPDATE users SET password_hash=? WHERE id=?",
                           (generate_password_hash(request.form["password"]), g.user["id"]))
                db.commit()
                flash("Mot de passe modifié.", "success")
        return redirect(url_for("profile"))

    if request.method == "POST" and action == "avatar":
        file = request.files.get("avatar")
        data = file.read() if file else b""
        ext = detect_image_ext(data)
        if not data:
            flash("Choisissez d'abord une image.", "error")
        elif ext is None:
            flash("Format non supporté. Utilisez une image JPG, PNG ou WEBP.", "error")
        else:
            os.makedirs(AVATAR_DIR, exist_ok=True)
            remove_avatar_file(g.user["avatar"])
            filename = f"{g.user['id']}_{secrets.token_hex(4)}.{ext}"
            with open(os.path.join(AVATAR_DIR, filename), "wb") as f:
                f.write(data)
            db.execute("UPDATE users SET avatar=? WHERE id=?", (filename, g.user["id"]))
            db.commit()
            flash("Photo de profil mise à jour.", "success")
        return redirect(url_for("profile"))

    if request.method == "POST" and action == "avatar_remove":
        remove_avatar_file(g.user["avatar"])
        db.execute("UPDATE users SET avatar='' WHERE id=?", (g.user["id"],))
        db.commit()
        flash("Photo supprimée.", "success")
        return redirect(url_for("profile"))

    if request.method == "POST" and action == "delete":
        if not check_password_hash(g.user["password_hash"], request.form.get("current", "")):
            flash("Mot de passe incorrect : le compte n'a pas été supprimé.", "error")
            return redirect(url_for("profile"))
        remove_avatar_file(g.user["avatar"])
        db.execute("DELETE FROM users WHERE id=?", (g.user["id"],))
        db.commit()
        session.clear()
        flash("Votre compte a été supprimé.", "success")
        return redirect(url_for("login"))

    return render_template("profile.html")


# --------------------------------------------------------------------------
# Calcul de la quantité de matière : n = m / M
# --------------------------------------------------------------------------
# Exemples prêts à l'emploi : (formule, nom, masse molaire M en g/mol, masse m d'exemple en g)
_EXAMPLES = [
    ("H₂O", "Eau", 18.015, 36),
    ("CO₂", "Dioxyde de carbone", 44.01, 22),
    ("O₂", "Dioxygène", 31.998, 16),
    ("H₂", "Dihydrogène", 2.016, 4),
    ("N₂", "Diazote", 28.014, 14),
    ("NH₃", "Ammoniac", 17.031, 8.5),
    ("CH₄", "Méthane", 16.043, 32),
    ("C₃H₈", "Propane", 44.097, 88),
    ("C₂H₆O", "Éthanol", 46.069, 23),
    ("CH₃COOH", "Acide acétique", 60.052, 30),
    ("NaCl", "Chlorure de sodium (sel)", 58.44, 5.85),
    ("NaOH", "Hydroxyde de sodium (soude)", 39.997, 20),
    ("HCl", "Chlorure d'hydrogène", 36.458, 3.65),
    ("H₂SO₄", "Acide sulfurique", 98.079, 49),
    ("HNO₃", "Acide nitrique", 63.012, 31.5),
    ("KCl", "Chlorure de potassium", 74.548, 7.45),
    ("CaCO₃", "Carbonate de calcium (calcaire)", 100.086, 50),
    ("NaHCO₃", "Hydrogénocarbonate de sodium", 84.006, 42),
    ("MgO", "Oxyde de magnésium", 40.304, 20),
    ("Al₂O₃", "Oxyde d'aluminium (alumine)", 101.961, 51),
    ("Fe₂O₃", "Oxyde de fer III (rouille)", 159.687, 80),
    ("CuSO₄", "Sulfate de cuivre II", 159.609, 16),
    ("AgNO₃", "Nitrate d'argent", 169.873, 17),
    ("C₆H₁₂O₆", "Glucose", 180.156, 18),
    ("C₁₂H₂₂O₁₁", "Saccharose (sucre)", 342.297, 34.2),
]
EXAMPLES = [
    {"formula": f, "name": name, "molar": M, "mass": m, "n": m / M}
    for f, name, M, m in _EXAMPLES
]


@app.route("/calcul", methods=["GET", "POST"])
@login_required
def calcul():
    db = get_db()
    uid = g.user["id"]
    form = {"mass": "", "molar": ""}
    error = None
    bad = set()

    if request.method == "POST":
        form = {"mass": request.form.get("mass", "").strip(),
                "molar": request.form.get("molar", "").strip()}
        m = parse_positive_number(form["mass"])
        M = parse_positive_number(form["molar"])
        if m is None:
            bad.add("mass")
        if M is None:
            bad.add("molar")
        if bad:
            error = ("Entrez uniquement des nombres strictement positifs, "
                     "par exemple 18 ou 18,015. Les lettres et les symboles sont refusés.")
        else:
            n = m / M
            if not math.isfinite(n):
                bad = {"mass", "molar"}
                error = "Le résultat est trop grand pour être calculé."
            else:
                db.execute(
                    "INSERT INTO calculations (user_id, mass, molar_mass, moles, created_at) VALUES (?,?,?,?,?)",
                    (uid, m, M, n, datetime.now().isoformat(timespec="seconds")),
                )
                db.commit()
                flash("Calcul enregistré dans l'historique.", "success")
                return redirect(url_for("calcul"))

    history = db.execute(
        "SELECT id, mass, molar_mass, moles, created_at FROM calculations "
        "WHERE user_id = ? ORDER BY id DESC LIMIT 50", (uid,)).fetchall()
    stats = db.execute(
        "SELECT COUNT(*) AS total, AVG(moles) AS avg_n, MIN(moles) AS min_n, MAX(moles) AS max_n "
        "FROM calculations WHERE user_id = ?", (uid,)).fetchone()
    page = render_template("calcul.html", form=form, error=error, bad=bad,
                           history=history, stats=stats, examples=EXAMPLES,
                           latest=history[0] if history and not error else None)
    return page, (422 if error else 200)


@app.route("/calcul/<int:calc_id>/delete", methods=["POST"])
@login_required
def calcul_delete(calc_id):
    db = get_db()
    db.execute("DELETE FROM calculations WHERE id = ? AND user_id = ?", (calc_id, g.user["id"]))
    db.commit()
    flash("Calcul supprimé de l'historique.", "success")
    return redirect(url_for("calcul"))


@app.route("/calcul/clear", methods=["POST"])
@login_required
def calcul_clear():
    db = get_db()
    db.execute("DELETE FROM calculations WHERE user_id = ?", (g.user["id"],))
    db.commit()
    flash("Historique vidé.", "success")
    return redirect(url_for("calcul"))


# --------------------------------------------------------------------------
# Espace admin : messages reçus via le formulaire de contact
# --------------------------------------------------------------------------
@app.route("/admin/messages")
@admin_required
def admin_messages():
    rows = get_db().execute("SELECT * FROM messages ORDER BY id DESC").fetchall()
    return render_template("admin_messages.html", messages=rows)


@app.route("/admin/messages/<int:msg_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_message(msg_id):
    db = get_db()
    db.execute("UPDATE messages SET is_read = 1 - is_read WHERE id = ?", (msg_id,))
    db.commit()
    return redirect(url_for("admin_messages"))


@app.route("/admin/messages/<int:msg_id>/delete", methods=["POST"])
@admin_required
def admin_delete_message(msg_id):
    db = get_db()
    db.execute("DELETE FROM messages WHERE id = ?", (msg_id,))
    db.commit()
    flash("Message supprimé.", "success")
    return redirect(url_for("admin_messages"))


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def error_page(err):
    return render_template("error.html", error=err), err.code


init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", host="127.0.0.1", port=5000)