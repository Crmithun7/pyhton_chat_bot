# app.py
from datetime import datetime, timedelta
import os, secrets, hashlib
from pathlib import Path
from flask import Flask, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, join_room, leave_room, emit
from socketio.exceptions import ConnectionRefusedError
import jwt as pyjwt
from sqlalchemy import func

print(">>> Starting backend in THREADING mode (eventlet disabled).")

# ---------- Config ----------
CLIENT_DIR = os.getenv("CLIENT_DIR", str(Path(__file__).parent / "client"))
app = Flask(__name__, static_folder=CLIENT_DIR, static_url_path="")
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET","dev-secret"),
    JWT_SECRET_KEY=os.getenv("JWT_SECRET","change-this-in-prod"),
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=int(os.getenv("JWT_HOURS","12"))),
    SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL","sqlite:///app.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={"connect_args":{"check_same_thread":False}},
)
db = SQLAlchemy(app)
jwt = JWTManager(app)
sio = SocketIO(app, async_mode="threading", cors_allowed_origins="*",
               logger=False, engineio_logger=False)

# ---------- Models ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
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

with app.app_context(): db.create_all()

# ---------- Helpers ----------
_ALPHABET="ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
def gen_code():
    while True:
        c="".join(secrets.choice(_ALPHABET) for _ in range(6))
        if not User.query.filter_by(code=c).first(): return c

def room_for(a:int,b:int)->str:
    x,y=sorted([a,b])
    return "pair-" + hashlib.sha256(f"pair:{x}:{y}".encode()).hexdigest()[:32]

def _decode_jwt(token:str):
    if not token: return None
    if token.startswith("Bearer "): token = token[7:]
    try:
        return pyjwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
    except Exception as e:
        print("JWT decode error:", e)
        return None

USER_SIDS, SID_USERS = {}, {}

# ---------- REST ----------
@app.post("/auth/register")
def register():
    d=request.get_json(force=True) or {}
    u=(d.get("username") or "").strip(); p=(d.get("password") or "").strip()
    if not u or not p: return {"error":"username and password required"},400
    if User.query.filter_by(username=u).first(): return {"error":"username already exists"},409
    user=User(username=u,password_hash=generate_password_hash(p),code=gen_code())
    db.session.add(user); db.session.commit()
    tok=create_access_token(identity=user.id, additional_claims={"username":user.username})
    return {"access_token":tok,"user":{"id":user.id,"username":user.username,"code":user.code}}

@app.post("/auth/login")
def login():
    d=request.get_json(force=True) or {}
    u=(d.get("username") or "").strip(); p=(d.get("password") or "").strip()
    user=User.query.filter_by(username=u).first()
    if not user or not check_password_hash(user.password_hash,p): return {"error":"invalid credentials"},401
    tok=create_access_token(identity=user.id, additional_claims={"username":user.username})
    return {"access_token":tok,"user":{"id":user.id,"username":user.username,"code":user.code}}

@app.get("/auth/me")
@jwt_required()
def me():
    uid=get_jwt_identity(); user=User.query.get(uid)
    if not user: return {"error":"user not found"},404
    return {"id":user.id,"username":user.username,"code":user.code}

@app.post("/id")
@jwt_required()
def regen_code():
    uid=get_jwt_identity(); user=User.query.get(uid)
    if not user: return {"error":"user not found"},404
    if (request.get_json(force=True) or {}).get("action")=="regenerate_code":
        user.code=gen_code(); db.session.commit()
    return {"id":user.id,"username":user.username,"code":user.code}

@app.get("/search")
@jwt_required()
def search_users():
    q=(request.args.get("q") or "").strip()
    if not q: return {"results":[]}
    rows=[]; seen=set()
    for u in list(User.query.filter(User.code==q.upper())) + \
             list(User.query.filter(func.lower(User.username).like(func.lower(f"{q}%"))).limit(10)):
        if u.id in seen: continue
        seen.add(u.id); rows.append({"id":u.id,"username":u.username,"code":u.code})
    return {"results":rows[:10]}

@app.get("/messages/<room>")
@jwt_required()
def get_messages(room):
    msgs=(Message.query.filter_by(room=room).order_by(Message.created_at.desc()).limit(50).all())
    return [{"id":m.id,"room":m.room,"sender_id":m.sender_id,"sender_name":m.sender_name,
             "text":m.text,"created_at":m.created_at.isoformat()} for m in msgs]

@app.get("/health")
def health(): return {"ok":True}

# ---------- Static (serve frontend) ----------
@app.get("/")
def index():
    idx=Path(app.static_folder)/"index.html"
    return send_from_directory(app.static_folder,"index.html") if idx.exists() else ({"error":"index.html not found"},404)

@app.get("/<path:fn>")
def spa(fn):
    root=Path(app.static_folder).resolve(); tgt=(root/fn).resolve()
    if not str(tgt).startswith(str(root)): return {"error":"forbidden"},403
    if tgt.is_file(): return send_from_directory(root,fn)
    return send_from_directory(root,"index.html")

# ---------- Socket.IO ----------
@sio.on("connect")
def sio_connect(auth):
    token=None
    if isinstance(auth,dict): token=auth.get("token")
    token = token or request.args.get("token") or request.headers.get("Authorization")
    if not token: raise ConnectionRefusedError("missing token")
    payload=_decode_jwt(token)
    if not payload: raise ConnectionRefusedError("bad token")
    try: uid=int(payload.get("sub"))
    except: raise ConnectionRefusedError("invalid sub")
    USER_SIDS[uid]=request.sid; SID_USERS[request.sid]=uid
    sio.save_session(request.sid,{"uid":uid,"username":payload.get("username")})
    emit("connected",{"uid":uid})

@sio.on("disconnect")
def sio_disc():
    sid=request.sid; uid=SID_USERS.pop(sid,None)
    if uid and USER_SIDS.get(uid)==sid: USER_SIDS.pop(uid,None)

@sio.on("join_room")
def sio_join(d):
    r=(d or {}).get("room"); 
    join_room(r) if r else None

@sio.on("leave_room")
def sio_leave(d):
    r=(d or {}).get("room"); 
    leave_room(r) if r else None

def _pair(me_sid, me_id, peer):
    rm=room_for(me_id, peer.id)
    join_room(rm)
    peer_sid=USER_SIDS.get(peer.id)
    if peer_sid: join_room(rm, sid=peer_sid)
    me_payload={"id":me_id,"username":sio.get_session(me_sid)["username"]}
    peer_payload={"id":peer.id,"username":peer.username,"code":peer.code}
    sio.emit("paired",{"room":rm,"peer":peer_payload},to=me_sid)
    if peer_sid: sio.emit("paired",{"room":rm,"peer":me_payload},to=peer_sid)

@sio.on("pair_with_code")
def sio_pair(d):
    sess=sio.get_session(request.sid)
    if not sess: emit("pair_error",{"error":"not authorized"}); return
    code=((d or {}).get("peer_code") or "").strip().upper()
    peer=User.query.filter_by(code=code).first()
    if not peer: emit("pair_error",{"error":"peer not found"}); return
    if peer.id==sess["uid"]: emit("pair_error",{"error":"cannot pair with yourself"}); return
    _pair(request.sid, sess["uid"], peer)

@sio.on("send_message")
def sio_msg(d):
    sess=sio.get_session(request.sid); 
    if not sess: return
    rm=(d or {}).get("room") or ""; txt=((d or {}).get("text") or "").strip()
    if not rm or not txt: return
    m=Message(room=rm,sender_id=sess["uid"],sender_name=sess["username"],text=txt)
    db.session.add(m); db.session.commit()
    emit("new_message",{"id":m.id,"room":rm,"sender_id":m.sender_id,"sender_name":m.sender_name,
                        "text":m.text,"created_at":m.created_at.isoformat()},room=rm)

@sio.on("rtc-offer")
def rtc_offer(d):
    rm=(d or {}).get("room"); sdp=(d or {}).get("sdp")
    if rm and sdp: emit("rtc-offer",{"room":rm,"sdp":sdp},room=rm,include_self=False)

@sio.on("rtc-answer")
def rtc_answer(d):
    rm=(d or {}).get("room"); sdp=(d or {}).get("sdp")
    if rm and sdp: emit("rtc-answer",{"room":rm,"sdp":sdp},room=rm,include_self=False)

@sio.on("rtc-ice")
def rtc_ice(d):
    rm=(d or {}).get("room"); cand=(d or {}).get("candidate")
    if rm and cand: emit("rtc-ice",{"room":rm,"candidate":cand},room=rm,include_self=False)

@sio.on("set_voice_variant")
def voice_variant(d):
    sess=sio.get_session(request.sid)
    if not sess: return
    emit("voice_variant",{"room":(d or {}).get("room"),"from":sess["username"],
                          "variant":(d or {}).get("variant","lady"),
                          "custom":(d or {}).get("custom",{})},room=(d or {}).get("room"))

# ---------- Main ----------
if __name__=="__main__":
    sio.run(app, host="0.0.0.0", port=int(os.getenv("PORT","5000")))
