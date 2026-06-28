import os, io, secrets, datetime, random, base64
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# New imports for image QR + OTP flow
import qrcode
from io import BytesIO

# Crypto imports (already used)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# For image/audio/video helpers
from PIL import Image
import soundfile as sf

# (If you use any video libs elsewhere, keep them; this file uses simple trailer method for video)
# App config - keep your MySQL URI here (unchanged from your original)
DB_URI = os.environ.get("DATABASE_URL") or "mysql+pymysql://root:nandu15nandu2005@localhost/stegano_db"
SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret-key"

UPLOAD_FOLDER = "uploads"
STEGO_FOLDER = "stego_store"
ALLOWED_IMAGE = {"png","jpg","jpeg","bmp"}
ALLOWED_AUDIO = {"wav"}
ALLOWED_VIDEO = {"mp4","avi"}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SQLALCHEMY_DATABASE_URI=DB_URI,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# -----------------------
# Models (Message extended with token/ciphertext/otp)
# -----------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    media_type = db.Column(db.String(20), nullable=False, default='image')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    downloaded_at = db.Column(db.DateTime, nullable=True)

    # New fields for token/ciphertext/otp flow
    token = db.Column(db.String(128), nullable=True, unique=True)
    ciphertext = db.Column(db.Text, nullable=True)   # base64 encoded ciphertext
    otp = db.Column(db.String(16), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)

class TransferHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(100), nullable=False)
    receiver = db.Column(db.String(100), nullable=False)
    file_type = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)

with app.app_context():
    db.create_all()
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(STEGO_FOLDER, exist_ok=True)

@login_manager.user_loader
def load_user(uid): return User.query.get(int(uid))

# -----------------------
# Crypto helpers (existing)
# -----------------------
MAGIC=b"STEGO1"; SALT=16; NONCE=12
def _kdf(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode())

def encrypt_message(data: bytes, password: str) -> bytes:
    import os
    salt = os.urandom(SALT); key = _kdf(password, salt)
    g = AESGCM(key); nonce = os.urandom(NONCE)
    ct = g.encrypt(nonce, data, None)
    return MAGIC + salt + nonce + ct

def decrypt_message(payload: bytes, password: str) -> bytes:
    assert payload.startswith(MAGIC), "bad header"
    o = len(MAGIC); salt = payload[o:o+SALT]; o += SALT
    nonce = payload[o:o+NONCE]; o += NONCE
    ct = payload[o:]
    key = _kdf(password, salt)
    return AESGCM(key).decrypt(nonce, ct, None)

# -----------------------
# Bit helpers (existing)
# -----------------------
def _bits(b):
    for x in b:
        for i in range(7,-1,-1): yield (x>>i) & 1

def _bits2bytes(bits):
    out=bytearray(); acc=0; c=0
    for b in bits:
        acc=(acc<<1)|(b&1); c+=1
        if c==8: out.append(acc); acc=0; c=0
    return bytes(out)

# -----------------------
# IMAGE embed/extract (existing LSB functions kept)
# -----------------------
def img_embed(cover_path, payload: bytes, out_path):
    img = Image.open(cover_path).convert("RGB")
    px = list(img.getdata()); flat=[]
    for r,g,b in px: flat += [r,g,b]
    need = 32 + len(payload)*8
    if need > len(flat): raise ValueError("payload too large for this image")
    L = len(payload)
    header = [(L>>i)&1 for i in range(31,-1,-1)]
    bits = header + list(_bits(payload))
    for i,b in enumerate(bits): flat[i] = (flat[i] & 0xFE) | b
    new = [(flat[i],flat[i+1],flat[i+2]) for i in range(0,len(flat),3)]
    out = Image.new("RGB", img.size); out.putdata(new); out.save(out_path, "PNG")

def img_extract(stego_path) -> bytes:
    img = Image.open(stego_path).convert("RGB")
    flat=[]; 
    for r,g,b in img.getdata(): flat += [r,g,b]
    L=0
    for i in range(32): L=(L<<1)|(flat[i]&1)
    bits=[flat[32+i]&1 for i in range(L*8)]
    return _bits2bytes(bits)

# -----------------------
# AUDIO embed/extract (existing)
# -----------------------
import soundfile as sf
def audio_embed_wav(cover_wav, payload: bytes, out_wav):
    data, sr = sf.read(cover_wav, dtype='int16')
    mono = data[:,0] if data.ndim==2 else data
    header = len(payload).to_bytes(4,'big')
    bits = list(_bits(header + payload))
    if len(bits) > mono.size:
        raise ValueError("payload too large for wav")
    mod = mono.copy()
    for i,b in enumerate(bits): mod[i] = (mod[i] & ~1) | b
    if data.ndim==1: out = mod
    else:
        out = data.copy(); out[:,0] = mod
    sf.write(out_wav, out, sr, subtype='PCM_16')

def audio_extract_wav(stego_wav) -> bytes:
    data, sr = sf.read(stego_wav, dtype='int16')
    mono = data[:,0] if data.ndim==2 else data
    L=0
    for i in range(32): L = (L<<1) | (mono[i] & 1)
    bits=[(mono[32+i] & 1) for i in range(L*8)]
    return _bits2bytes(bits)

# -----------------------
# VIDEO embed/extract (existing trailer approach)
# -----------------------
V_MAGIC=b"VSTEGO1"
def video_embed_trailer(cover_path, payload: bytes, out_path):
    with open(cover_path,'rb') as f: content=f.read()
    trailer = V_MAGIC + len(payload).to_bytes(4,'big') + payload
    with open(out_path,'wb') as f:
        f.write(content); f.write(trailer)

def video_extract_trailer(stego_path) -> bytes:
    with open(stego_path,'rb') as f: data=f.read()
    i = data.rfind(V_MAGIC)
    if i == -1: raise ValueError("no payload")
    i += len(V_MAGIC)
    L = int.from_bytes(data[i:i+4], 'big'); i += 4
    payload = data[i:i+L]
    if len(payload) != L: raise ValueError("corrupt payload")
    return payload

# -----------------------
# utils
# -----------------------
def _allowed(filename, mt):
    if "." not in filename: return False
    ext = filename.rsplit(".",1)[1].lower()
    return (ext in ALLOWED_IMAGE if mt=="image" else
            ext in ALLOWED_AUDIO if mt=="audio" else
            ext in ALLOWED_VIDEO if mt=="video" else False)

def log_transfer(sender, receiver, file_type, status):
    t = TransferHistory(sender=sender, receiver=receiver, file_type=file_type, status=status)
    db.session.add(t); db.session.commit()

# -----------------------
# Routes: auth + dashboard (unchanged)
# -----------------------
@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method=="POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        if not u or not p:
            flash("Username and password required"); return redirect(url_for("signup"))
        if User.query.filter_by(username=u).first():
            flash("Username already exists"); return redirect(url_for("signup"))
        user = User(username=u, password_hash=generate_password_hash(p))
        db.session.add(user); db.session.commit()
        flash("Account created. Please log in."); return redirect(url_for("login"))
    return render_template("login.html", signup=True)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        user = User.query.filter_by(username=u).first()
        if user and check_password_hash(user.password_hash, p):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", username=current_user.username)

# -----------------------
# IMAGE: QR -> AES -> embed (PVD-simulated) + OTP flow (UPDATED to Option 2)
# -----------------------

# helper: create QR PNG bytes from message (we will encode token URL into QR)
def generate_qr_bytes(message: str) -> bytes:
    """Create a PNG QR code for `message` and return bytes."""
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(message)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

@app.route("/embed_image", methods=["GET", "POST"])
@login_required
def embed_image():
    if request.method == "POST":
        cover = request.files.get("cover")
        msg = request.form.get("message", "")
        pw = request.form.get("password", "")
        receiver = request.form.get("receiver", "").strip()

        if not cover or cover.filename == "" or not _allowed(cover.filename, "image"):
            flash("Upload a PNG/JPG/BMP cover image")
            return redirect(url_for("embed_image"))

        rec_user = User.query.filter_by(username=receiver).first()
        if not rec_user:
            flash("Receiver not found")
            return redirect(url_for("embed_image"))

        # generate a unique token (to embed in QR)
        token = secrets.token_urlsafe(12)

        # ✅ get your local IP dynamically so QR works on phone
        import socket
        local_ip = socket.gethostbyname(socket.gethostname())
        qr_url = f"http://{local_ip}:5000/view/{token}"
        # 1) generate QR bytes from the QR URL (so scanning opens /view/<token>)
        try:
            qr_bytes = generate_qr_bytes(qr_url)
        except Exception as e:
            flash(f"QR generation failed: {e}")
            return redirect(url_for("embed_image"))

        # 2) encrypt the plaintext message and store ciphertext in DB (base64)
        try:
            ciphertext = encrypt_message(msg.encode("utf-8"), pw)
            ciphertext_b64 = base64.b64encode(ciphertext).decode()
        except Exception as e:
            flash(f"Encryption failed: {e}")
            return redirect(url_for("embed_image"))

        # 3) save uploaded cover and embed the QR PNG bytes into the image
        filename = secure_filename(cover.filename)
        cover_path = os.path.join(UPLOAD_FOLDER, filename)
        cover.save(cover_path)
        out_name = f"stego-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(4)}.png"
        out_path = os.path.join(STEGO_FOLDER, out_name)

        try:
            img_embed(cover_path, qr_bytes, out_path)  # embed QR PNG bytes
        except Exception as e:
            flash(f"Embedding failed: {e}")
            return redirect(url_for("embed_image"))

        # 4) create DB record for message and store token + ciphertext
        m = Message(
            sender_id=current_user.id,
            receiver_id=rec_user.id,
            filename=out_name,
            media_type="image",
            token=token,
            ciphertext=ciphertext_b64,
        )
        db.session.add(m)
        db.session.commit()
        log_transfer(current_user.username, rec_user.username, "image", "SENT")

        flash("Image stego sent successfully. Receiver will generate OTP when attempting extraction.")
        return redirect(url_for("dashboard"))

    return render_template("embed_image.html")

@app.route("/inbox")
@login_required
def inbox():
    rows = db.session.query(Message, User).join(User, Message.sender_id==User.id).filter(Message.receiver_id==current_user.id).order_by(Message.id.desc()).all()
    return render_template("inbox.html", messages=rows)

@app.route("/history")
@login_required
def history():
    sent = db.session.query(Message, User).join(User, Message.receiver_id==User.id).filter(Message.sender_id==current_user.id).order_by(Message.id.desc()).all()
    received = db.session.query(Message, User).join(User, Message.sender_id==User.id).filter(Message.receiver_id==current_user.id).order_by(Message.id.desc()).all()
    logs = TransferHistory.query.order_by(TransferHistory.id.desc()).limit(300).all()
    return render_template("history.html", sent=sent, received=received, logs=logs)

@app.route("/stego/<int:mid>")
@login_required
def stego_download(mid:int):
    m = Message.query.get_or_404(mid)
    if m.receiver_id != current_user.id and m.sender_id != current_user.id:
        return ("Forbidden", 403)
    path = os.path.join(STEGO_FOLDER, m.filename)
    if not os.path.exists(path): return ("Not found",404)
    if m.receiver_id == current_user.id and m.downloaded_at is None:
        m.downloaded_at = datetime.datetime.utcnow(); db.session.commit()
    return send_file(path, as_attachment=True, download_name=m.filename)

@app.route("/extract/<int:mid>", methods=["GET","POST"])
@login_required
def extract_view(mid:int):
    m = Message.query.get_or_404(mid)
    if m.receiver_id != current_user.id:
        return ("Forbidden", 403)
    sender_name = User.query.get(m.sender_id).username

    # On GET: generate OTP for receiver automatically (if not present or expired)
    if request.method == "GET":
        if not m.otp or (m.otp_expiry and m.otp_expiry < datetime.datetime.utcnow()):
            m.otp = str(random.randint(100000, 999999))
            m.otp_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
            db.session.commit()
            # For demo we flash OTP to receiver UI; in production deliver via secure channel (SMS/email)
            flash(f"OTP generated for this extraction (demo): {m.otp} — valid for 5 minutes.")
        return render_template("extract.html", message=m, sender_name=sender_name)

    # POST: receiver requests to download/extract QR image for scanning
    if request.method == "POST":
        action = request.form.get("action","download_qr")
        if action == "download_qr":
            path = os.path.join(STEGO_FOLDER, m.filename)
            try:
                qr_bytes = img_extract(path)   # returns the QR PNG bytes we embedded earlier
            except Exception as e:
                flash(f"Failed to extract QR: {e}"); log_transfer(current_user.username, sender_name, m.media_type, "EXTRACT_FAIL"); return redirect(url_for("extract_view", mid=mid))
            buf = io.BytesIO(qr_bytes); buf.seek(0)
            log_transfer(sender_name, current_user.username, m.media_type, "QR_EXTRACTED")
            return send_file(buf, as_attachment=True, download_name="embedded_qr.png", mimetype="image/png")
        else:
            flash("Unknown action"); return redirect(url_for("extract_view", mid=mid))

# Public route: when QR is scanned it points here: /view/<token>
# This page asks for OTP (and password) to reveal the hidden message.
@app.route("/view/<token>", methods=["GET", "POST"])
def view_token(token):
    # Find the message in the database using the token
    m = Message.query.filter_by(token=token).first()
    if not m:
        return render_template("view_notfound.html"), 404

    # Step 1: When the receiver first opens the link (GET request)
    if request.method == "GET":
        # Show OTP + password form
        return render_template("view_token.html", token=token)

    # Step 2: When receiver submits OTP and password (POST request)
    otp_input = request.form.get("otp", "").strip()
    password = request.form.get("password", "").strip()

    # Validate OTP existence and expiry
    if not m.otp or not m.otp_expiry:
        flash("❌ No OTP generated yet. The receiver must request a new OTP.", "danger")
        return render_template("view_token.html", token=token)

    # Check OTP expiry
    if datetime.datetime.utcnow() > m.otp_expiry:
        flash("⚠️ OTP expired. Please request a new one.", "warning")
        return render_template("view_token.html", token=token)

    # Check OTP correctness
    if otp_input != m.otp:
        flash("❌ Invalid OTP entered. Try again.", "danger")
        return render_template("view_token.html", token=token)

    # Step 3: OTP is valid — decrypt the message using password
    try:
        if not m.ciphertext:
            flash("⚠️ No encrypted data found for this message.", "warning")
            return render_template("view_token.html", token=token)

        # Base64 decode and AES decrypt
        ciphertext = base64.b64decode(m.ciphertext)
        plaintext = decrypt_message(ciphertext, password)
        decrypted_text = plaintext.decode("utf-8", errors="replace")

    except Exception as e:
        print("Decryption error:", e)
        flash("❌ Decryption failed. Wrong password or corrupted ciphertext.", "danger")
        return render_template("view_token.html", token=token)

    # Step 4: Clear OTP after successful single use
    try:
        m.otp = None
        m.otp_expiry = None
        db.session.commit()
    except:
        pass

    # Step 5: Show the decrypted message to the receiver
    return render_template("view_result.html", message=decrypted_text)

# -----------------------
# AUDIO routes (unchanged)
# -----------------------
@app.route("/embed_audio", methods=["GET","POST"])
@login_required
def embed_audio():
    if request.method=="POST":
        cover = request.files.get("cover")
        msg = request.form.get("message","")
        pw  = request.form.get("password","")
        receiver = request.form.get("receiver","").strip()
        if not cover or cover.filename=="" or not _allowed(cover.filename, "audio"):
            flash("Upload a WAV cover"); return redirect(url_for("embed_audio"))
        rec_user = User.query.filter_by(username=receiver).first()
        if not rec_user: flash("Receiver not found"); return redirect(url_for("embed_audio"))
        filename = secure_filename(cover.filename); cover_path = os.path.join(UPLOAD_FOLDER, filename); cover.save(cover_path)
        payload = encrypt_message(msg.encode("utf-8"), pw)
        out_name = f"stego-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(4)}.wav"
        out_path = os.path.join(STEGO_FOLDER, out_name)
        audio_embed_wav(cover_path, payload, out_path)
        m = Message(sender_id=current_user.id, receiver_id=rec_user.id, filename=out_name, media_type="audio")
        db.session.add(m); db.session.commit(); log_transfer(current_user.username, rec_user.username, "audio", "SENT")
        flash("Audio stego sent"); return redirect(url_for("dashboard"))
    return render_template("embed_audio.html")

@app.route("/extract_audio/<int:mid>", methods=["GET","POST"])
@login_required
def extract_audio(mid:int):
    m = Message.query.get_or_404(mid)
    if m.receiver_id != current_user.id:
        return ("Forbidden", 403)
    sender_name = User.query.get(m.sender_id).username
    if request.method=="POST":
        pw = request.form.get("password","")
        path = os.path.join(STEGO_FOLDER, m.filename)
        try:
            payload = audio_extract_wav(path)
            plaintext = decrypt_message(payload, pw)
        except Exception as e:
            flash(f"Failed: {e}"); 
            log_transfer(current_user.username, sender_name, m.media_type, "DECRYPT_FAIL")
            return redirect(url_for("extract_audio", mid=mid))
        buf = io.BytesIO(plaintext); buf.seek(0)
        log_transfer(sender_name, current_user.username, m.media_type, "DECRYPT_OK")
        return send_file(buf, as_attachment=True, download_name="message.txt", mimetype="text/plain")
    return render_template("extract_audio.html", message=m, sender_name=sender_name)

# -----------------------
# VIDEO routes (unchanged)
# -----------------------
@app.route("/embed_video", methods=["GET","POST"])
@login_required
def embed_video():
    if request.method=="POST":
        cover = request.files.get("cover")
        msg = request.form.get("message","")
        pw  = request.form.get("password","")
        receiver = request.form.get("receiver","").strip()
        if not cover or cover.filename=="" or not _allowed(cover.filename, "video"):
            flash("Upload an MP4/AVI cover"); return redirect(url_for("embed_video"))
        rec_user = User.query.filter_by(username=receiver).first()
        if not rec_user: flash("Receiver not found"); return redirect(url_for("embed_video"))
        filename = secure_filename(cover.filename); cover_path = os.path.join(UPLOAD_FOLDER, filename); cover.save(cover_path)
        payload = encrypt_message(msg.encode("utf-8"), pw)
        ext = filename.rsplit(".",1)[1].lower()
        out_name = f"stego-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(4)}.{ext}"
        out_path = os.path.join(STEGO_FOLDER, out_name)
        video_embed_trailer(cover_path, payload, out_path)
        m = Message(sender_id=current_user.id, receiver_id=rec_user.id, filename=out_name, media_type="video")
        db.session.add(m); db.session.commit(); log_transfer(current_user.username, rec_user.username, "video", "SENT")
        flash("Video stego sent"); return redirect(url_for("dashboard"))
    return render_template("embed_video.html")

@app.route("/extract_video/<int:mid>", methods=["GET","POST"])
@login_required
def extract_video(mid:int):
    m = Message.query.get_or_404(mid)
    if m.receiver_id != current_user.id:
        return ("Forbidden", 403)
    sender_name = User.query.get(m.sender_id).username
    if request.method=="POST":
        pw = request.form.get("password","")
        path = os.path.join(STEGO_FOLDER, m.filename)
        try:
            payload = video_extract_trailer(path)
            plaintext = decrypt_message(payload, pw)
        except Exception as e:
            flash(f"Failed: {e}"); 
            log_transfer(current_user.username, sender_name, m.media_type, "DECRYPT_FAIL")
            return redirect(url_for("extract_video", mid=mid))
        buf = io.BytesIO(plaintext); buf.seek(0)
        log_transfer(sender_name, current_user.username, m.media_type, "DECRYPT_OK")
        return send_file(buf, as_attachment=True, download_name="message.txt", mimetype="text/plain")
    return render_template("extract_video.html", message=m, sender_name=sender_name)

# -----------------------
# Run server
# -----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
