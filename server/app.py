from datetime import datetime, timedelta
import os, secrets, hashlib
from pathlib import Path
from flask import Flask, request, render_template, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_cors import CORS
import jwt as pyjwt  # PyJWT for manual decode in sockets (no eventlet)
from sqlalchemy import func

print(">>> Starting backend in THREADING mode (eventlet disabled).")

# ---------------- Config ----------------

class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET", "dev-secret")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET", "change-this-in-prod")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=int(os.getenv("JWT_HOURS", "12")))
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False}}
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

    # Frontend root (can override with env var CLIENT_DIR)
    CLIENT_DIR = os.getenv(
        "CLIENT_DIR",
        r"C:\Users\crmit\Desktop\python_chat_bot\client"
    )

# ------------- App / DB / JWT / SIO -------------
app = Flask(__name__)
app.config.from_object(Config)
CORS(app, origins=Config.CORS_ORIGINS, supports_credentials=True)

# Serve frontend from CLIENT_DIR at site root
app.static_folder = app.config["CLIENT_DIR"]
app.static_url_path = ""  # so /main.js maps to <CLIENT_DIR>/main.js

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Force threading async mode; DO NOT import eventlet anywhere
sio = SocketIO(
    app,
    cors_allowed_origins=Config.CORS_ORIGINS,
    async_mode="threading",
    logger=False,
    engineio_logger=False
)

# ----------------- Models -----------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    email = db.Column(db.String(120), unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    code = db.Column(db.String(8), unique=True, index=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True)
    room = db.Column(db.String(64), index=True, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    sender_name = db.Column(db.String(64), nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class CallLog(db.Model):
    __tablename__ = "call_logs"
    id = db.Column(db.Integer, primary_key=True)
    room = db.Column(db.String(64), index=True, nullable=False)
    caller_id = db.Column(db.Integer, index=True)
    callee_id = db.Column(db.Integer, index=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)
    voice_variant = db.Column(db.String(16))  # 'woman' | 'girl' | 'lady' | 'custom'

with app.app_context():
    db.create_all()

# ----------------- Helpers -----------------
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
def gen_code():
    while True:
        code = "".join(secrets.choice(_ALPHABET) for _ in range(6))
        if not User.query.filter_by(code=code).first():
            return code

def room_for(uid_a: int, uid_b: int) -> str:
    a, b = sorted([uid_a, uid_b])
    h = hashlib.sha256(f"pair:{a}:{b}".encode()).hexdigest()[:32]
    return f"pair-{h}"

USER_SIDS = {}   # uid -> sid
SID_USERS = {}   # sid -> uid

def _decode_jwt(token: str):
    try:
        return pyjwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
    except Exception:
        return None

# --------------- Auth routes ---------------
@app.post("/auth/register")
def register():
    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    email = (data.get("email") or "").strip() or None
    if not username or not password:
        return {"error": "username and password required"}, 400
    if User.query.filter_by(username=username).first():
        return {"error": "username already exists"}, 409
    if email and User.query.filter_by(email=email).first():
        return {"error": "email already exists"}, 409
    u = User(username=username, email=email,
             password_hash=generate_password_hash(password),
             code=gen_code())
    db.session.add(u); db.session.commit()
    access = create_access_token(identity=u.id, additional_claims={"username": u.username})
    refresh = create_refresh_token(identity=u.id)
    return {"access_token": access, "refresh_token": refresh,
            "user": {"id": u.id, "username": u.username, "code": u.code}}

@app.post("/auth/login")
def login():
    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    u = User.query.filter_by(username=username).first()
    if not u or not check_password_hash(u.password_hash, password):
        return {"error": "invalid credentials"}, 401
    access = create_access_token(identity=u.id, additional_claims={"username": u.username})
    refresh = create_refresh_token(identity=u.id)
    return {"access_token": access, "refresh_token": refresh,
            "user": {"id": u.id, "username": u.username, "code": u.code}}

@app.post("/auth/refresh")
@jwt_required(refresh=True)
def refresh():
    uid = get_jwt_identity()
    u = User.query.get(uid)
    if not u: return {"error": "user not found"}, 404
    access = create_access_token(identity=uid, additional_claims={"username": u.username})
    return {"access_token": access}

@app.get("/auth/me")
@jwt_required()
def me():
    uid = get_jwt_identity()
    u = User.query.get(uid)
    if not u: return {"error": "user not found"}, 404
    return {"id": u.id, "username": u.username, "email": u.email, "code": u.code}

# --------------- ID + Search + Messages ---------------
@app.post("/id")
@jwt_required()
def set_or_regen_id():
    uid = get_jwt_identity()
    u = User.query.get(uid)
    if not u: return {"error": "user not found"}, 404
    data = request.get_json(force=True) or {}
    if (data.get("action") or "") == "regenerate_code":
        u.code = gen_code()
        db.session.commit()
    return {"id": u.id, "username": u.username, "code": u.code}

@app.get("/search")
@jwt_required()
def search_users():
    q = (request.args.get("q") or "").strip()
    if not q: return {"results": []}
    by_code = User.query.filter(User.code == q.upper()).all()
    by_name = (User.query
               .filter(func.lower(User.username).like(func.lower(f"{q}%")))
               .limit(10).all())
    seen, results = set(), []
    for u in by_code + by_name:
        if u.id in seen: continue
        seen.add(u.id)
        results.append({"id": u.id, "username": u.username, "code": u.code})
    return {"results": results[:10]}

@app.get("/messages/<room>")
@jwt_required()
def get_messages(room):
    msgs = (Message.query.filter_by(room=room)
            .order_by(Message.created_at.desc())
            .limit(50).all())
    return [{
        "id": m.id, "room": m.room, "sender_id": m.sender_id,
        "sender_name": m.sender_name, "text": m.text,
        "created_at": m.created_at.isoformat()
    } for m in msgs]

@app.get("/health")
def health():
    return {"ok": True}

# ---------- Static / SPA routes (keep after API routes) ----------
@app.get("/")
def serve_index():
    root = Path(app.static_folder).resolve()
    index = root / "index.html"
    if index.exists():
        return send_from_directory(root, "index.html")
    return {"error": f"index.html not found in {root}"}, 404

@app.get("/<path:filename>")
def serve_static_or_spa(filename: str):
    """
    If the requested file exists under CLIENT_DIR, serve it.
    Otherwise, fall back to index.html so client-side routing works.
    This route is placed after API routes to avoid intercepting them.
    """
    root = Path(app.static_folder).resolve()
    target = (root / filename).resolve()

    # prevent path traversal outside root
    if not str(target).startswith(str(root)):
        return {"error": "forbidden"}, 403

    if target.is_file():
        # Serve actual asset
        return send_from_directory(root, filename)

    # Fallback to SPA index.html
    index = root / "index.html"
    if index.exists():
        return send_from_directory(root, "index.html")

    return {"error": "not found"}, 404

# --------------- Socket.IO (threading) ---------------
@sio.on("connect")
def on_connect(auth):
    token = None
    if isinstance(auth, dict):
        token = auth.get("token")
    if not token:
        token = request.args.get("token")
    if not token:
        return False
    payload = _decode_jwt(token)
    if not payload:
        return False
    uid = int(payload.get("sub"))
    username = payload.get("username")
    USER_SIDS[uid] = request.sid
    SID_USERS[request.sid] = uid
    sio.save_session(request.sid, {"uid": uid, "username": username})

@sio.on("disconnect")
def on_disconnect():
    sid = request.sid
    uid = SID_USERS.pop(sid, None)
    if uid and USER_SIDS.get(uid) == sid:
        USER_SIDS.pop(uid, None)

@sio.on("join_room")
def on_join_room(data):
    room = (data or {}).get("room")
    if room: join_room(room)

@sio.on("leave_room")
def on_leave_room(data):
    room = (data or {}).get("room")
    if room: leave_room(room)

def _pair_room(me_id, peer):
    rm = room_for(me_id, peer.id)
    join_room(rm)
    emit("paired", {"room": rm, "peer": {"id": peer.id, "username": peer.username, "code": peer.code}})
    peer_sid = USER_SIDS.get(peer.id)
    if peer_sid:
        sess = sio.get_session(request.sid)
        sio.emit("incoming_pair", {"room": rm, "from": {"id": me_id, "username": sess["username"]}}, to=peer_sid)

@sio.on("pair_with_code")
def on_pair_with_code(data):
    sess = sio.get_session(request.sid)
    if not sess: return
    me_id = sess["uid"]
    code = ((data or {}).get("peer_code") or "").strip().upper()
    peer = User.query.filter_by(code=code).first()
    if not peer:
        emit("pair_error", {"error": "peer not found"}); return
    if peer.id == me_id:
        emit("pair_error", {"error": "cannot pair with yourself"}); return
    _pair_room(me_id, peer)

@sio.on("send_message")
def on_send_message(data):
    sess = sio.get_session(request.sid)
    if not sess: return
    rm = (data or {}).get("room") or ""
    txt = ((data or {}).get("text") or "").strip()
    if not rm or not txt: return
    msg = Message(room=rm, sender_id=sess["uid"], sender_name=sess["username"], text=txt)
    db.session.add(msg); db.session.commit()
    emit("new_message", {
        "id": msg.id, "room": rm, "sender_id": msg.sender_id,
        "sender_name": msg.sender_name, "text": msg.text,
        "created_at": msg.created_at.isoformat()
    }, room=rm)

# WebRTC signaling
@sio.on("rtc-offer")
def rtc_offer(data):
    rm = (data or {}).get("room"); sdp = (data or {}).get("sdp")
    if rm and sdp:
        emit("rtc-offer", {"room": rm, "sdp": sdp}, room=rm, include_self=False)

@sio.on("rtc-answer")
def rtc_answer(data):
    rm = (data or {}).get("room"); sdp = (data or {}).get("sdp")
    if rm and sdp:
        emit("rtc-answer", {"room": rm, "sdp": sdp}, room=rm, include_self=False)

@sio.on("rtc-ice")
def rtc_ice(data):
    rm = (data or {}).get("room"); cand = (data or {}).get("candidate")
    if rm and cand:
        emit("rtc-ice", {"room": rm, "candidate": cand}, room=rm, include_self=False)

# Voice preset event (client-side FX; server just rebroadcasts & stores)
@sio.on("set_voice_variant")
def set_voice_variant(data):
    sess = sio.get_session(request.sid)
    if not sess: return
    rm = (data or {}).get("room")
    variant = ((data or {}).get("variant") or "lady").lower()
    custom = (data or {}).get("custom") or {}
    log = CallLog(room=rm, caller_id=sess["uid"], voice_variant=variant)
    db.session.add(log); db.session.commit()
    emit("voice_variant", {"room": rm, "from": sess["username"], "variant": variant, "custom": custom}, room=rm)

# --------------- Main ---------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    sio.run(app, host="0.0.0.0", port=port)
