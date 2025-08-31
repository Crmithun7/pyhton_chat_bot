# app.py
from datetime import datetime, timedelta
import os, secrets, hashlib
from pathlib import Path
from flask import Flask, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, join_room, leave_room, emit, disconnect
from flask_cors import CORS
import jwt as pyjwt
from sqlalchemy import func

print(">>> Starting backend in THREADING mode (no websocket upgrades).")

class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET", "dev-secret")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET", "change-me")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=int(os.getenv("JWT_HOURS", "12")))
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False}}
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")
    CLIENT_DIR = os.getenv("CLIENT_DIR", str(Path.cwd() / "client"))

app = Flask(__name__)
app.config.from_object(Config)
CORS(app, origins=Config.CORS_ORIGINS, supports_credentials=True)

app.static_folder = app.config["CLIENT_DIR"]
app.static_url_path = ""

db = SQLAlchemy(app)
jwt = JWTManager(app)

sio = SocketIO(
    app,
    cors_allowed_origins=Config.CORS_ORIGINS,
    async_mode="threading",
    logger=False,
    engineio_logger=False,
    allow_upgrades=False,          # force long-polling (works with Werkzeug)
    ping_timeout=30,
    ping_interval=12,
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
    voice_variant = db.Column(db.String(16))

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

def _decode_jwt(token: str):
    try:
        return pyjwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
    except Exception:
        return None

UID_TO_SID = {}
SID_TO_UID = {}
SID_TO_NAME = {}
PENDING = {}

# ----------------- Auth -----------------
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
    access  = create_access_token(identity=str(u.id), additional_claims={"username": u.username})
    refresh = create_refresh_token(identity=str(u.id))
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
    access  = create_access_token(identity=str(u.id), additional_claims={"username": u.username})
    refresh = create_refresh_token(identity=str(u.id))
    return {"access_token": access, "refresh_token": refresh,
            "user": {"id": u.id, "username": u.username, "code": u.code}}

@app.post("/auth/refresh")
@jwt_required(refresh=True)
def refresh():
    uid = get_jwt_identity()
    u = db.session.get(User, int(uid)) if uid is not None else None
    if not u: return {"error": "user not found"}, 401
    access = create_access_token(identity=str(u.id), additional_claims={"username": u.username})
    return {"access_token": access}

@app.get("/auth/me")
@jwt_required()
def me():
    uid = get_jwt_identity()
    u = db.session.get(User, int(uid)) if uid is not None else None
    if not u: return {"error": "user not found"}, 401
    return {"id": u.id, "username": u.username, "email": u.email, "code": u.code}

# ----------------- ID / Search / Messages -----------------
@app.post("/id")
@jwt_required()
def regen_code():
    uid = int(get_jwt_identity())
    u = db.session.get(User, uid)
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
def health(): return {"ok": True}

@app.get("/favicon.ico")
def favicon(): return ("", 204)

# silence chrome devtools well-known lookups
@app.get("/.well-known/<path:rest>")
def well_known(rest): return ("", 204)

# ----------------- Static / SPA -----------------
@app.get("/")
def serve_index():
    root = Path(app.static_folder).resolve()
    idx = root / "index.html"
    if idx.exists(): return send_from_directory(root, "index.html")
    return {"error": f"index.html not found in {root}"}, 404

@app.get("/<path:filename>")
def serve_static(filename: str):
    root = Path(app.static_folder).resolve()
    target = (root / filename).resolve()
    if not str(target).startswith(str(root)): return {"error": "forbidden"}, 403
    if target.is_file(): return send_from_directory(root, filename)
    idx = root / "index.html"
    if idx.exists(): return send_from_directory(root, "index.html")
    return {"error": "not found"}, 404

# ----------------- Socket.IO -----------------
@sio.on("connect")
def sio_connect(auth):
    token = None
    if isinstance(auth, dict):
        token = auth.get("token")
    token = token or request.args.get("token")
    if not token:
        print("SIO connect blocked: no token"); return False
    claims = _decode_jwt(token)
    if not claims:
        print("SIO connect blocked: bad token"); return False
    try:
        uid = int(claims.get("sub"))
    except Exception:
        print("SIO connect blocked: sub not int"); return False
    username = claims.get("username", f"user{uid}")
    UID_TO_SID[uid] = request.sid
    SID_TO_UID[request.sid] = uid
    SID_TO_NAME[request.sid] = username
    emit("connected", {"uid": uid})

@sio.on("disconnect")
def sio_disconnect():
    sid = request.sid
    uid = SID_TO_UID.pop(sid, None)
    SID_TO_NAME.pop(sid, None)
    if uid and UID_TO_SID.get(uid) == sid:
        UID_TO_SID.pop(uid, None)

@sio.on("pair_with_code")
def pair_with_code(data):
    sid = request.sid
    me_uid = SID_TO_UID.get(sid)
    if not me_uid: emit("pair_error", {"error": "not authenticated"}); return
    code = ((data or {}).get("peer_code") or "").strip().upper()
    peer = User.query.filter_by(code=code).first()
    if not peer: emit("pair_error", {"error": "peer not found"}); return
    if peer.id == me_uid: emit("pair_error", {"error": "cannot pair with yourself"}); return
    peer_sid = UID_TO_SID.get(peer.id)
    if not peer_sid: emit("pair_error", {"error": "peer is offline"}); return

    rm = room_for(me_uid, peer.id)
    PENDING[rm] = {"from_uid": me_uid, "to_uid": peer.id, "from_sid": sid, "to_sid": peer_sid}
    sio.server.enter_room(sid, rm)  # initiator joins
    emit("pair_pending")
    sio.emit("pair_request", {"room": rm, "from": {"id": me_uid, "username": SID_TO_NAME.get(sid,"")}}, to=peer_sid)

@sio.on("pair_accept")
def pair_accept(data):
    rm = (data or {}).get("room")
    if not rm or rm not in PENDING: emit("pair_error", {"error": "no such pair"}); return
    rec = PENDING.pop(rm)
    sio.server.enter_room(request.sid, rm)
    if rec.get("from_sid"):
        try: sio.server.enter_room(rec["from_sid"], rm)
        except Exception: pass
    sio.emit("paired", {"room": rm}, to=rec["from_sid"])
    emit("paired", {"room": rm})

@sio.on("pair_reject")
def pair_reject(data):
    rm = (data or {}).get("room")
    if not rm or rm not in PENDING: return
    rec = PENDING.pop(rm)
    sio.emit("pair_error", {"error": "peer declined"}, to=rec["from_sid"])

@sio.on("send_message")
def send_message(data):
    sid = request.sid
    uid = SID_TO_UID.get(sid)
    name = SID_TO_NAME.get(sid, f"user{uid or ''}")
    rm = (data or {}).get("room") or ""
    txt = ((data or {}).get("text") or "").strip()
    if not rm or not txt or not uid: return
    msg = Message(room=rm, sender_id=uid, sender_name=name, text=txt)
    db.session.add(msg); db.session.commit()
    emit("new_message", {
        "id": msg.id, "room": rm, "sender_id": msg.sender_id,
        "sender_name": msg.sender_name, "text": msg.text,
        "created_at": msg.created_at.isoformat()
    }, room=rm)

# ---- WebRTC signaling passthrough ----
@sio.on("rtc-offer")
def rtc_offer(data):
    rm = (data or {}).get("room"); sdp = (data or {}).get("sdp")
    if rm and sdp: emit("rtc-offer", {"room": rm, "sdp": sdp}, room=rm, include_self=False)

@sio.on("rtc-answer")
def rtc_answer(data):
    rm = (data or {}).get("room"); sdp = (data or {}).get("sdp")
    if rm and sdp: emit("rtc-answer", {"sdp": sdp}, room=rm, include_self=False)

@sio.on("rtc-ice")
def rtc_ice(data):
    rm = (data or {}).get("room"); cand = (data or {}).get("candidate")
    if rm and cand: emit("rtc-ice", {"candidate": cand}, room=rm, include_self=False)

@sio.on("set_voice_variant")
def set_voice_variant(data):
    rm = (data or {}).get("room")
    variant = ((data or {}).get("variant") or "lady").lower()
    emit("voice_variant", {"room": rm, "from": SID_TO_NAME.get(request.sid,""), "variant": variant}, room=rm)

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    ssl_ctx = "adhoc" if os.getenv("HTTPS", "0") == "1" else None  # set HTTPS=1 to enable self-signed HTTPS
    sio.run(app, host="0.0.0.0", port=port, ssl_context=ssl_ctx)
