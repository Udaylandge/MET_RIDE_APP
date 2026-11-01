"""Security tests: rate limiting, lockout, password policy, private files, refresh hardening, headers.
Run:  python tests/test_security.py
"""
import io, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.update({"MONGO_URI": "mongodb://x/y", "SECRET_KEY": "test-secret-key-0123456789-abcdefghij",
                   "BYPASS_EMAIL": "true", "DEV_RETURN_OTP": "true", "ADMIN_EMAIL": "boss@example.com",
                   "NEW_ADMIN_PASSWORD": "Adm1n!Pass", "RATE_LIMIT_ENABLED": "true"})
import mongomock
import extensions

DB = mongomock.MongoClient().get_database("t")
class DBProxy:
    def __getattr__(self, n): return getattr(DB, n)
    def __getitem__(self, n): return DB[n]
extensions.mongo.init_app = lambda app: setattr(extensions.mongo, "db", DBProxy())

from app import create_app
from routes.security import reset_rate_limits, signed_upload_url, _ser

PASS = FAIL = 0
def check(name, cond, info=""):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  [PASS] {name}")
    else: FAIL += 1; print(f"  [FAIL] {name} {info}")
def J(r): return r.get_json(silent=True) or {}
def H(t): return {"Authorization": f"Bearer {t}"}
JPEG = b"\xff\xd8\xff\xe0" + b"0" * 2000

print("\n== Startup safety ==")
saved = os.environ["SECRET_KEY"]
os.environ["SECRET_KEY"] = "short"
try:
    create_app(); check("weak SECRET_KEY refuses to start", False)
except RuntimeError as e:
    check("weak SECRET_KEY refuses to start", "SECRET_KEY" in str(e))
os.environ["SECRET_KEY"] = ""
try:
    create_app(); check("empty SECRET_KEY refuses to start", False)
except RuntimeError:
    check("empty SECRET_KEY refuses to start", True)
os.environ["SECRET_KEY"] = saved

app = create_app(); c = app.test_client()
UP = app.config["UPLOAD_FOLDER"]

print("\n== Headers / health ==")
r = c.get("/api/health")
check("health ok", r.status_code == 200 and J(r)["status"] == "ok")
check("nosniff + frame deny headers", r.headers.get("X-Content-Type-Options") == "nosniff" and r.headers.get("X-Frame-Options") == "DENY")
check("API responses are no-store", "no-store" in r.headers.get("Cache-Control", ""))
check("404 is JSON not HTML", c.get("/api/nothing").get_json()["success"] is False)

print("\n== Password policy ==")
def otp_for(email):
    return J(c.post("/api/auth/request-otp", json={"email": email})).get("dev_otp")
otp = otp_for("pw@bkc.met.edu")
for pw, why in (("short1", "too short"), ("longpasswordnodigits", "no digit"), ("1234567890", "no letter")):
    r = c.post("/api/register", json={"name": "P", "email": "pw@bkc.met.edu", "password": pw, "otp": otp})
    check(f"weak password rejected ({why})", r.status_code == 400 and "assword" in J(r)["message"], r.data[:100])
r = c.post("/api/register", json={"name": "P", "email": "pw@bkc.met.edu", "password": "Strong123", "otp": otp})
check("strong password accepted", r.status_code == 200, r.data[:150])
TOK = J(r)["token"]; UID = J(r)["user"]["id"]

print("\n== Injection / bad input ==")
for payload in ({"email": {"$ne": ""}, "password": {"$ne": ""}}, {"email": ["a"], "password": 5}, None):
    r = c.post("/api/login", json=payload) if payload is not None else c.post("/api/login", data="not json", content_type="text/plain")
    check(f"login with hostile payload {str(payload)[:30]} -> no 500/200", r.status_code in (400, 401), r.status_code)
r = c.post("/api/admin/login", json={"email": "boss@example.com", "password": {"$ne": ""}})
check("admin login with object password -> no 500/200", r.status_code in (400, 401), r.status_code)
reset_rate_limits()

print("\n== Account lockout ==")
for i in range(5):
    r = c.post("/api/login", json={"email": "pw@bkc.met.edu", "password": "Wrong1234"})
check("5 wrong passwords -> still 401", r.status_code == 401)
r = c.post("/api/login", json={"email": "pw@bkc.met.edu", "password": "Strong123"})
check("account locked: even the correct password -> 429", r.status_code == 429 and "locked" in J(r)["message"].lower(), r.data[:120])
DB.users.update_one({"email": "pw@bkc.met.edu"}, {"$unset": {"lock_until": ""}})
r = c.post("/api/login", json={"email": "pw@bkc.met.edu", "password": "Strong123"})
check("after lock expires the correct password works", r.status_code == 200)
reset_rate_limits()

print("\n== Rate limiting ==")
codes = [c.post("/api/login", json={"email": "nobody@bkc.met.edu", "password": "Whatever1"}).status_code for _ in range(14)]
check("login spam gets 429", 429 in codes and codes[0] == 401, codes)
r = c.post("/api/login", json={"email": "nobody@bkc.met.edu", "password": "x"})
check("429 has Retry-After header", r.status_code == 429 and r.headers.get("Retry-After"))
codes = [c.post("/api/admin/login", json={"email": "boss@example.com", "password": "nope"}).status_code for _ in range(10)]
check("admin login spam gets 429", 429 in codes, codes)
reset_rate_limits()
codes = [c.post("/api/auth/request-otp", json={"email": f"u{i}@bkc.met.edu"}).status_code for i in range(12)]
check("OTP request spam gets 429", 429 in codes, codes)
reset_rate_limits()

print("\n== Private documents ==")
for ep in ("upload-id", "upload-receipt"):
    r = c.post(f"/api/profile/{ep}", headers=H(TOK), data={"image": (io.BytesIO(JPEG), "x")}, content_type="multipart/form-data")
    check(f"{ep} ok", r.status_code == 200, r.data[:150])
url = J(r).get("id_card_url") or ""
check("API returns a SIGNED url", "?t=" in url, url)
path = url.replace("http://localhost", "")
check("signed url downloads the file", c.get(path).status_code == 200)
bare = path.split("?")[0]
check("same url WITHOUT signature -> 403", c.get(bare).status_code == 403)
check("same url with garbage signature -> 403", c.get(bare + "?t=abc").status_code == 403)
other = [f for f in os.listdir(UP) if f.startswith("fee_receipt")][0]
tok_for_id = path.split("?t=")[1]
check("signature for file A does not open file B", c.get(f"/uploads/{other}?t={tok_for_id}").status_code == 403)
check("path traversal blocked", c.get(f"/uploads/..%2Fapp.py?t={tok_for_id}").status_code in (403, 404))
check("/api/uploads alias also needs signature", c.get(f"/api/uploads/{os.path.basename(bare)}").status_code == 403)
with app.app_context():
    expired = _ser().dumps(os.path.basename(bare))
import routes.security as sec
old = sec.FILE_URL_TTL; sec.FILE_URL_TTL = -1
check("expired signature -> 403", c.get(f"{bare}?t={expired}").status_code == 403)
sec.FILE_URL_TTL = old
r = c.get("/api/profile", headers=H(TOK)); pj = J(r)
check("profile urls are signed too", "?t=" in str(pj.get("id_card_url") or pj.get("data", {}).get("id_card_url") or ""), str(pj)[:200])

print("\n== Token refresh hardening ==")
r = c.post("/api/login", json={"email": "pw@bkc.met.edu", "password": "Strong123"}); RT = J(r)["refresh_token"]
check("valid refresh works", c.post("/api/auth/refresh", json={"refresh_token": RT}).status_code == 200)
check("garbage refresh token -> 401", c.post("/api/auth/refresh", json={"refresh_token": "abc"}).status_code == 401)
check("non-string refresh token -> 401", c.post("/api/auth/refresh", json={"refresh_token": {"a": 1}}).status_code == 401)
DB.users.update_one({"email": "pw@bkc.met.edu"}, {"$set": {"is_blocked": True}})
check("blocked user cannot refresh", c.post("/api/auth/refresh", json={"refresh_token": RT}).status_code == 401)
DB.users.update_one({"email": "pw@bkc.met.edu"}, {"$set": {"is_blocked": False}})
import jwt as pyjwt, datetime
forged = pyjwt.encode({"sub": UID, "role": "admin", "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)}, "change_me_in_production", algorithm="HS256")
check("token forged with the old default key is rejected", c.get("/api/admin/stats", headers=H(forged)).status_code == 401)
check("student token cannot use admin API", c.get("/api/admin/stats", headers=H(TOK)).status_code == 403)
none_tok = pyjwt.encode({"sub": UID, "role": "admin"}, None, algorithm="none")
check("alg=none token rejected", c.get("/api/admin/stats", headers=H(none_tok)).status_code == 401)

for f in os.listdir(UP):
    if f.startswith(("id_card_", "fee_receipt_")): os.remove(os.path.join(UP, f))   # tidy up test uploads
print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
