# server/app.py
import os, secrets, hashlib
from datetime import timedelta, datetime
from pathlib import Path

from flask import Flask, request, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash

from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from flask_jwt_extended.utils import decode_token  # robust decode for sockets

from flask_socketio import SocketIO, join_room, leave_room, emit

print(">>> Starting backend in THREADING mode (WS upgrades optional via ALLOW_WS).")

# ------------ Config ------------
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CLIENT_DIR = os.getenv("CLIENT_DIR", str(ROOT / "client"))
DB_PATH = os.getenv("DATABASE_URL", f"sqlite:///{ROOT/'instance'/'app.db'}")

class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET", secrets.token_hex(16))
    JWT_SECRET_KEY = os.getenv("JWT_SECRET", secrets.token_hex(32))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=int(os.getenv("JWT_HOURS", "12")))
    SQLALCHEMY_DATABASE_URI = DB_PATH
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False}}
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

app = Flask(__name__, static_folder=CLIENT_DIR, static_url_path="")
app.config.from_object(Config)
CORS(app, origins=Config.CORS_ORIGINS, supports_credentials=True)

db = SQLAlchemy(app)
jwt = JWTManager(app)

allow_ws = os.getenv("ALLOW_WS", "0") == "1"  # enable WebSocket upgrades in prod
sio = SocketIO(
    app,
    async_mode="threading",
    cors_allowed_origins=Config.CORS_ORIGINS,
    logger=False,
    engineio_logger=False,
    allow_upgrades=allow_ws,
    ping_interval=12,
    ping_timeout=30,
)

# ------------ Models ------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    email = db.Column(db.String(120), unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    code = db.Column(db.String(8), unique=True, index=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room = db.Column(db.String(64), index=True, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    sender_name = db.Column(db.String(64), nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class PairRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_id = db.Column(db.Integer, index=True, nullable=False)
    to_id = db.Column(db.Integer, index=True, nullable=False)
    status = db.Column(db.String(16), default="pending")  # pending|accepted|declined
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    (ROOT / "instance").mkdir(parents=True, exist_ok=True)
    db.create_all()

# ------------ Helpers ------------
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
def gen_code():
    while True:
        c = "".join(secrets.choice(_ALPHABET) for _ in range(6))
        if not User.query.filter_by(code=c).first():
            return c

def room_for(a: int, b: int) -> str:
    x, y = sorted([a, b])
    return "pair-" + hashlib.sha256(f"{x}:{y}".encode()).hexdigest()[:32]

USER_SIDS = {}   # uid -> sid
SID_USERS = {}   # sid -> uid

def _decode_access_token(token: str):
    try:
        claims = decode_token(token)  # uses Flask-JWT-Extended keys/options
        sub = claims.get("sub")
        uid = int(sub) if str(sub).isdigit() else None
        return uid, claims.get("username")
    except Exception:
        return None, None

# ------------ Auth API ------------
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
    # IMPORTANT: make sub a string to avoid PyJWT "Subject must be a string"
    access = create_access_token(identity=str(u.id), additional_claims={"username": u.username})
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
    access = create_access_token(identity=str(u.id), additional_claims={"username": u.username})
    refresh = create_refresh_token(identity=str(u.id))
    return {"access_token": access, "refresh_token": refresh,
            "user": {"id": u.id, "username": u.username, "code": u.code}}

@app.post("/auth/refresh")
@jwt_required(refresh=True)
def refresh():
    uid = get_jwt_identity()
    u = db.session.get(User, int(uid))
    if not u: return {"error": "user not found"}, 404
    access = create_access_token(identity=str(u.id), additional_claims={"username": u.username})
    return {"access_token": access}

@app.get("/auth/me")
def whoami():
    # nice UX: if missing/invalid token just say "not logged in"
    auth = request.headers.get("Authorization", "")
    token = auth.split("Bearer ", 1)[-1].strip() if "Bearer " in auth else None
    if not token:
        return {"logged_in": False}, 200
    uid, _ = _decode_access_token(token)
    if not uid:
        return {"logged_in": False}, 200
    u = db.session.get(User, uid)
    if not u: return {"logged_in": False}, 200
    return {"logged_in": True, "id": u.id, "username": u.username, "email": u.email, "code": u.code}, 200

# ------------ App API ------------
@app.post("/id")
@jwt_required()
def regen_code():
    uid = int(get_jwt_identity())
    u = db.session.get(User, uid)
    if not u: return {"error": "user not found"}, 404
    u.code = gen_code(); db.session.commit()
    return {"id": u.id, "username": u.username, "code": u.code}

@app.get("/search")
@jwt_required()
def search_users():
    q = (request.args.get("q") or "").strip().upper()
    if not q: return {"results": []}
    by_code = User.query.filter(User.code == q).all()
    by_name = (User.query.filter(func.lower(User.username).like(func.lower(f"{q}%"))).limit(10).all())
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
            .order_by(Message.created_at.desc()).limit(50).all())
    return [{
        "id": m.id, "room": m.room, "sender_id": m.sender_id,
        "sender_name": m.sender_name, "text": m.text,
        "created_at": m.created_at.isoformat()
    } for m in msgs]

@app.get("/health")
def health():
    return {"ok": True}

# ------------ Static (SPA) ------------
@app.get("/")
def serve_index():
    idx = Path(app.static_folder) / "index.html"
    if idx.exists(): return send_from_directory(app.static_folder, "index.html")
    return {"error": f"index.html not found in {app.static_folder}"}, 404

@app.get("/<path:filename>")
def serve_assets(filename):
    root = Path(app.static_folder).resolve()
    target = (root / filename).resolve()
    if str(target).startswith(str(root)) and target.is_file():
        return send_from_directory(root, filename)
    # SPA fallback
    idx = root / "index.html"
    if idx.exists(): return send_from_directory(root, "index.html")
    return {"error": "not found"}, 404

# ------------ Socket.IO ------------
@sio.on("connect")
def sio_connect(auth):
    token = None
    if isinstance(auth, dict):
        token = auth.get("token")
    if not token:
        token = request.args.get("token")
    uid, username = _decode_access_token(token or "")
    if not uid:
        return False  # reject
    USER_SIDS[uid] = request.sid
    SID_USERS[request.sid] = uid
    emit("whoami", {"id": uid, "username": username})

@sio.on("disconnect")
def sio_disconnect():
    sid = request.sid
    uid = SID_USERS.pop(sid, None)
    if uid and USER_SIDS.get(uid) == sid:
        USER_SIDS.pop(uid, None)

# ---- pairing with request/accept flow ----
@sio.on("pair_with_code")
def sio_pair_with_code(data):
    me = SID_USERS.get(request.sid)
    if not me: return
    code = ((data or {}).get("peer_code") or "").strip().upper()
    peer = User.query.filter_by(code=code).first()
    if not peer:
        emit("pair_error", {"error": "peer not found"}); return
    if peer.id == me:
        emit("pair_error", {"error": "cannot pair with yourself"}); return
    pr = PairRequest(from_id=me, to_id=peer.id, status="pending")
    db.session.add(pr); db.session.commit()
    peer_sid = USER_SIDS.get(peer.id)
    if peer_sid:
        emit("pair_request", {
            "request_id": pr.id,
            "from": {"id": me, "username": User.query.get(me).username}
        }, to=peer_sid)
    emit("pair_request_sent", {"request_id": pr.id})

@sio.on("pair_response")
def sio_pair_response(data):
    me = SID_USERS.get(request.sid)
    if not me: return
    rid = int((data or {}).get("request_id") or 0)
    accept = bool((data or {}).get("accept"))
    pr = db.session.get(PairRequest, rid)
    if not pr or pr.to_id != me or pr.status != "pending":
        emit("pair_error", {"error": "invalid request"}); return
    pr.status = "accepted" if accept else "declined"; db.session.commit()
    from_sid = USER_SIDS.get(pr.from_id)
    if not accept:
        if from_sid: emit("pair_declined", {"request_id": rid}, to=from_sid)
        emit("pair_declined", {"request_id": rid}); return
    # accepted -> tell both clients the room id
    rm = room_for(pr.from_id, pr.to_id)
    if from_sid: emit("paired", {"room": rm}, to=from_sid)
    emit("paired", {"room": rm})

@sio.on("join_room")
def sio_join(data):
    rm = (data or {}).get("room")
    if rm: join_room(rm)

@sio.on("leave_room")
def sio_leave(data):
    rm = (data or {}).get("room")
    if rm: leave_room(rm)

# chat
@sio.on("send_message")
def sio_send_message(data):
    uid = SID_USERS.get(request.sid)
    if not uid: return
    rm = (data or {}).get("room") or ""
    txt = ((data or {}).get("text") or "").strip()
    if not rm or not txt: return
    u = db.session.get(User, uid)
    msg = Message(room=rm, sender_id=uid, sender_name=u.username, text=txt)
    db.session.add(msg); db.session.commit()
    emit("new_message", {
        "id": msg.id, "room": rm, "sender_id": uid,
        "sender_name": u.username, "text": msg.text,
        "created_at": msg.created_at.isoformat()
    }, room=rm)

# signaling
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

# ------------ Main ------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    # Allow Werkzeug only when explicitly enabled (e.g., on Render)
    run_kwargs = {}
    if os.getenv("ALLOW_UNSAFE_WERKZEUG", "0") == "1":
        run_kwargs["allow_unsafe_werkzeug"] = True

    # Turn on websocket upgrades in real deployments if you want WS (not just polling)
    if os.getenv("ALLOW_WS", "0") == "1":
        sio.server.eio.allow_upgrades = True  # safe to toggle before run

    sio.run(app, host="0.0.0.0", port=port, **run_kwargs)
