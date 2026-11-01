"""End-to-end backend test (mongomock + Flask test client + Socket.IO test client).
Run:  python tests/test_e2e.py
"""
import io, os, sys, copy
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.update({"MONGO_URI": "mongodb://x/y", "SECRET_KEY": "test-secret-key-0123456789-abcdefghij", "RATE_LIMIT_ENABLED": "false", "BYPASS_EMAIL": "true",
                   "DEV_RETURN_OTP": "true", "ADMIN_EMAIL": "boss@example.com",
                   "NEW_ADMIN_PASSWORD": "Adm1n!Pass", "ADMIN_PASSWORD": ""})
import mongomock
import extensions

DB = mongomock.MongoClient().get_database("t")


class RidesProxy:
    """mongomock has no $near/2dsphere, so strip that clause for the nearby test only."""
    def __init__(self, col): self._c = col
    def find(self, query=None, *a, **k):
        q = copy.deepcopy(query or {}); q.pop("start_location", None)
        return self._c.find(q, *a, **k)
    def __getattr__(self, n): return getattr(self._c, n)


class DBProxy:
    def __getattr__(self, n):
        return RidesProxy(DB.rides) if n == "rides" else getattr(DB, n)
    def __getitem__(self, n): return DB[n]


extensions.mongo.init_app = lambda app: setattr(extensions.mongo, "db", DBProxy())

from app import create_app
from extensions import socketio, mongo

app = create_app()
c = app.test_client()
PASS = FAIL = 0


def check(name, cond, info=""):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  [PASS] {name}")
    else: FAIL += 1; print(f"  [FAIL] {name} {info}")


def H(tok): return {"Authorization": f"Bearer {tok}"}
def J(r): return r.get_json(silent=True) or {}
JPEG = b"\xff\xd8\xff\xe0" + b"0" * 2000


def register(email, name, pw="Passw0rd!"):
    r = c.post("/api/auth/request-otp", json={"email": email}); otp = J(r).get("dev_otp")
    r = c.post("/api/register", json={"name": name, "email": email, "password": pw, "otp": otp})
    return r, J(r)


def make_verified(email, name):
    r, j = register(email, name)
    tok, uid = j["token"], j["user"]["id"]
    for ep, nm in (("upload-id", "a"), ("upload-receipt", "b")):
        c.post(f"/api/profile/{ep}", headers=H(tok), data={"image": (io.BytesIO(JPEG), nm)},
               content_type="multipart/form-data")   # note: filename has NO extension
    c.post(f"/api/admin/users/{uid}/verify", headers=H(ADMIN), json={"action": "approve"})
    return tok, uid


print("\n== 1. Admin ==")
r = c.post("/api/admin/login", json={"email": "boss@example.com", "password": "bad"})
check("admin login wrong password -> 401", r.status_code == 401)
r = c.post("/api/admin/login", json={"email": " Boss@Example.com ", "password": "Adm1n!Pass"})
check("admin login (any domain, spaces/caps) -> 200", r.status_code == 200, r.data[:200])
ADMIN = J(r).get("token") or J(r).get("access_token")

print("\n== 2. OTP / register security ==")
r = c.post("/api/auth/request-otp", json={"email": "x@gmail.com"})
check("non-college email rejected", r.status_code == 400)
r = c.post("/api/auth/request-otp", json={"email": "ann@bkc.met.edu"}); otp = J(r).get("dev_otp")
check("OTP issued", r.status_code == 200 and otp)
stored = DB.users.find_one({"email": "ann@bkc.met.edu"})
check("OTP stored hashed, not plaintext", "otp" not in stored and otp not in str(stored.get("otp_hash")))
r = c.post("/api/auth/request-otp", json={"email": "ann@bkc.met.edu"})
check("OTP resend throttled -> 429", r.status_code == 429)
r = c.post("/api/register", json={"name": "Ann", "email": "ann@bkc.met.edu", "password": "Passw0rd!"})
check("register WITHOUT otp -> 400 (no free token)", r.status_code == 400)
for i in range(5):
    r = c.post("/api/auth/verify-otp", json={"email": "ann@bkc.met.edu", "otp": "000000"})
check("5 wrong OTPs then locked", "Too many" in J(c.post("/api/auth/verify-otp", json={"email": "ann@bkc.met.edu", "otp": otp})).get("message", ""))
DB.users.update_one({"email": "ann@bkc.met.edu"}, {"$set": {"otpCreatedAt": None}})
r = c.post("/api/auth/request-otp", json={"email": "ann@bkc.met.edu"}); otp = J(r).get("dev_otp")
DB.users.update_one({"email": "ann@bkc.met.edu"}, {"$set": {"otp_expires_at": __import__("datetime").datetime(2000, 1, 1)}})
r = c.post("/api/auth/verify-otp", json={"email": "ann@bkc.met.edu", "otp": otp})
check("expired OTP rejected", r.status_code == 400 and "expired" in J(r)["message"])
DB.users.delete_one({"email": "ann@bkc.met.edu"})

r, j = register("ann@bkc.met.edu", "Ann")
check("register with valid OTP -> 200 + token", r.status_code == 200 and j.get("token"))
ANN, ANN_ID = j["token"], j["user"]["id"]
r = c.post("/api/register", json={"name": "Hacker", "email": "ann@bkc.met.edu", "password": "Hacked123!", "otp": "123456"})
check("cannot re-register / take over existing account", r.status_code in (400, 409))
r = c.post("/api/login", json={"email": "ann@bkc.met.edu", "password": "Hacked123!"})
check("attacker password does NOT work", r.status_code == 401)
r = c.post("/api/login", json={"email": "ann@bkc.met.edu", "password": "Passw0rd!"})
check("real password logs in", r.status_code == 200 and J(r)["user"]["is_verified"] is False)
r = c.post("/api/admin/login", json={"email": "ann@bkc.met.edu", "password": "Passw0rd!"})
check("student blocked from admin login -> 403", r.status_code == 403)

print("\n== 3. Documents & verification ==")
r = c.post("/api/profile/upload-id", headers=H(ANN), data={"image": (io.BytesIO(b"not an image at all"), "x.jpg")}, content_type="multipart/form-data")
check("fake/non-image file rejected", r.status_code == 400, r.data[:120])
r = c.post("/api/profile/upload-id", headers=H(ANN), data={"image": (io.BytesIO(JPEG), "photo")}, content_type="multipart/form-data")
check("ID upload, filename without extension -> 200", r.status_code == 200, r.data[:160])
r = c.post("/api/profile/upload-receipt", headers=H(ANN), data={"image": (io.BytesIO(JPEG), "receipt.jpg")}, content_type="multipart/form-data")
check("receipt upload -> 200", r.status_code == 200, r.data[:160])
check("status moved to pending after both docs", DB.users.find_one({"email": "ann@bkc.met.edu"}).get("verification_status") == "pending")
r = c.get("/api/profile", headers=H(ANN)); pj = J(r)
flat = str(pj)
check("profile reports NOT verified while pending", "'verification_status': 'pending'" in flat or "'verification_status': \"pending\"" in flat or pj.get("data", pj).get("verification_status") == "pending", flat[:300])
check("profile is_verified is false while pending", pj.get("data", pj).get("is_verified") in (False, None) and pj.get("user", {}).get("is_verified") in (False, None), flat[:300])
r = c.post("/api/rides", headers=H(ANN), json={"origin": "A", "destination": "B", "origin_lat": 20.0, "origin_lng": 73.78, "destination_lat": 20.01, "destination_lng": 73.79, "seats_available": 2})
check("unverified user cannot post ride -> 403", r.status_code == 403)
r = c.get("/api/admin/users?status=pending", headers=H(ADMIN)); us = J(r).get("users", [])
check("admin sees pending user with documents", any(u.get("email") == "ann@bkc.met.edu" for u in us), r.data[:200])
r = c.get("/api/admin/users?status=needs_action", headers=H(ADMIN))
check("needs_action filter works", r.status_code == 200 and J(r).get("count", 0) >= 1)
check("admin account not in review queue", not any(u.get("email") == "boss@example.com" for u in J(c.get("/api/admin/users", headers=H(ADMIN))).get("users", [])))
r = c.get("/api/admin/stats", headers=H(ADMIN)); check("admin stats 200", r.status_code == 200)
r = c.post(f"/api/admin/users/{ANN_ID}/verify", headers=H(ANN), json={"action": "approve"})
check("student cannot approve users -> 403", r.status_code == 403)
r = c.post(f"/api/admin/users/{ANN_ID}/verify", headers=H(ADMIN), json={"action": "approve"})
check("admin approve -> 200", r.status_code == 200, r.data[:160])
check("status now verified", DB.users.find_one({"email": "ann@bkc.met.edu"}).get("verification_status") == "verified")

print("\n== 4. Ride lifecycle ==")
BOB, BOB_ID = make_verified("bob@bkc.met.edu", "Bob")
CAL, CAL_ID = make_verified("cal@bkc.met.edu", "Cal")
ride_body = {"origin": "MET BKC", "destination": "Nashik Road", "origin_lat": 20.0059, "origin_lng": 73.7898,
             "destination_lat": 19.9615, "destination_lng": 73.8310, "departure_time": "2026-10-25T08:00:00",
             "seats_available": 2, "fare": 40, "upi_id": "ann@upi"}
r = c.post("/api/rides", headers=H(ANN), json=ride_body)
check("verified driver posts ride -> 201", r.status_code == 201, r.data[:200])
RIDE = J(r)["ride"]["id"] if "id" in J(r).get("ride", {}) else J(r)["ride"]["_id"]
r = c.get("/api/rides/nearby?latitude=20.0&longitude=73.78&radius=25.0&destination=", headers=H(BOB))
check("nearby search works (empty destination ok)", r.status_code == 200 and J(r)["count"] >= 1, r.data[:200])
r = c.get(f"/api/rides/{RIDE}", headers=H(BOB)); rd = J(r).get("ride", {})
check("ride detail has id/status/lat-lng (Android shape)", rd.get("id") == RIDE and rd.get("status") == "scheduled" and rd.get("origin_lat") == 20.0059, r.data[:200])
r = c.post(f"/api/rides/{RIDE}/request", headers=H(ANN), json={"seats_requested": 1})
check("driver cannot request own ride", r.status_code == 400)
r = c.post(f"/api/rides/{RIDE}/request", headers=H(BOB), json={"seats_requested": 1})
check("passenger requests seat -> 200", r.status_code == 200, r.data[:160])
r = c.post(f"/api/rides/{RIDE}/request", headers=H(BOB), json={"seats_requested": 1})
check("duplicate request -> 409", r.status_code == 409)
r = c.get("/api/notifications", headers=H(ANN)); n = J(r)
check("driver got a notification", n.get("unread_count", 0) >= 1 and n["notifications"][0]["type"] == "ride_request", r.data[:200])
nt = J(c.get("/api/notifications", headers=H(ANN)))["notifications"][0]
check("request notification names passenger, route and time", "Bob" in nt["body"] and "MET BKC" in nt["body"] and "08:00 AM" in nt["body"], nt["body"])
r = c.post(f"/api/rides/{RIDE}/accept/{BOB_ID}", headers=H(BOB))
check("passenger cannot accept -> 403", r.status_code == 403)
r = c.post(f"/api/rides/{RIDE}/accept/{BOB_ID}", headers=H(ANN))
check("driver accepts -> 200", r.status_code == 200, r.data[:160])
an = J(c.get("/api/notifications", headers=H(BOB)))["notifications"][0]
check("passenger notified: accepted + pickup time + OTP", an["type"] == "ride_accepted" and "08:00 AM" in an["body"] and "OTP" in an["body"], an["body"])
rd = J(c.get(f"/api/rides/{RIDE}", headers=H(BOB)))["ride"]
check("passenger sees 4-digit OTP + accepted", rd["request_status"] == "accepted" and len(str(rd["otp"])) == 4)
OTP = rd["otp"]
rd_driver = J(c.get(f"/api/rides/{RIDE}", headers=H(ANN)))["ride"]
check("driver sees passenger list but NOT the OTP", len(rd_driver["passengers"]) == 1 and not rd_driver.get("otp"))
rd_other = J(c.get(f"/api/rides/{RIDE}", headers=H(CAL)))["ride"]
check("other user sees no OTP / no passengers", not rd_other.get("otp") and rd_other["passengers"] == [])
r = c.post(f"/api/rides/{RIDE}/location", headers=H(ANN), json={"latitude": 20.0, "longitude": 73.8})
check("location rejected before ride starts -> 409", r.status_code == 409)
r = c.post(f"/api/rides/{RIDE}/complete", headers=H(ANN))
check("cannot complete before start -> 409", r.status_code == 409)
wrong = "0000" if OTP != "0000" else "1111"
r = c.post(f"/api/rides/{RIDE}/verify-otp", headers=H(ANN), json={"otp": wrong})
check("wrong ride OTP -> 400", r.status_code == 400)
r = c.post(f"/api/rides/{RIDE}/verify-otp", headers=H(BOB), json={"otp": OTP})
check("passenger cannot start ride -> 403", r.status_code == 403)

# Socket.IO
nosock = socketio.test_client(app, flask_test_client=c)
check("socket without token refused", not nosock.is_connected())
sd = socketio.test_client(app, auth={"token": ANN}); sp = socketio.test_client(app, auth={"token": BOB}); sc = socketio.test_client(app, auth={"token": CAL})
check("sockets connect with JWT", sd.is_connected() and sp.is_connected())
sp.emit("join_ride", {"ride_id": RIDE}); sc.emit("join_ride", {"ride_id": RIDE}); sd.emit("join_ride", {"ride_id": RIDE})

r = c.post(f"/api/rides/{RIDE}/verify-otp", headers=H(ANN), json={"otp": OTP})
check("driver starts ride with correct OTP -> 200", r.status_code == 200, r.data[:160])
check("ride is in_progress", J(c.get(f"/api/rides/{RIDE}", headers=H(BOB)))["ride"]["status"] == "in_progress")
ev = [e["name"] for e in sp.get_received()]
check("passenger socket got ride_status_update", "ride_status_update" in ev, ev)
sc.get_received()
sd.emit("update_location", {"ride_id": RIDE, "latitude": 20.003, "longitude": 73.785})
got = [e for e in sp.get_received() if e["name"] == "location_update"]
check("passenger receives live location over socket", got and abs(got[0]["args"][0]["latitude"] - 20.003) < 1e-9, got)
check("non-member (Cal) did NOT receive location", not [e for e in sc.get_received() if e["name"] == "location_update"])
sp.emit("update_location", {"ride_id": RIDE, "latitude": 1.0, "longitude": 1.0})
check("passenger cannot spoof driver location", J(c.get(f"/api/rides/{RIDE}", headers=H(BOB)))["ride"]["current_lat"] == 20.003)
r = c.post(f"/api/rides/{RIDE}/location", headers=H(ANN), json={"latitude": 20.004, "longitude": 73.786})
check("REST location update -> 200", r.status_code == 200)
r = c.post(f"/api/rides/{RIDE}/cancel", headers=H(BOB), json={"reason": "x"})
check("passenger cannot cancel after start -> 409", r.status_code == 409)
r = c.post(f"/api/rides/{RIDE}/rate", headers=H(BOB), json={"rating": 5})
check("cannot rate before completion -> 409", r.status_code == 409)
r = c.post(f"/api/rides/{RIDE}/complete", headers=H(ANN))
check("driver completes ride -> 200", r.status_code == 200, r.data[:160])
r = c.post(f"/api/rides/{RIDE}/rate", headers=H(BOB), json={"rating": 4, "review": "nice"})
check("passenger rates driver -> 200", r.status_code == 200, r.data[:160])
r = c.post(f"/api/rides/{RIDE}/rate", headers=H(BOB), json={"rating": 5})
check("double rating -> 409", r.status_code == 409)
check("driver avg rating updated to 4.0", DB.users.find_one({"email": "ann@bkc.met.edu"}).get("avg_rating") == 4.0)
r = c.get("/api/rides/my", headers=H(BOB)); check("passenger /rides/my lists ride", J(r)["count"] == 1 and J(r)["rides"][0]["status"] == "completed")
r = c.get("/api/profile/ride-history?page=1&limit=20", headers=H(BOB)); check("ride-history 200", r.status_code == 200, r.data[:150])
r = c.get("/api/dashboard", headers=H(BOB)); check("dashboard 200", r.status_code == 200, r.data[:150])

r = c.put("/api/profile", headers=H(ANN), json={"name": "Ann Driver", "department": "MCA", "upi_id": "ann@okaxis"})
check("PUT /api/profile updates name, department, UPI", r.status_code == 200 and J(r)["user"]["name"] == "Ann Driver" and J(r)["user"]["upi_id"] == "ann@okaxis", r.data[:160])
check("invalid UPI rejected", c.put("/api/profile", headers=H(ANN), json={"upi_id": "not a upi"}).status_code == 400)
check("empty name rejected", c.put("/api/profile", headers=H(ANN), json={"name": "  "}).status_code == 400)
check("role cannot be changed through profile update", c.put("/api/profile", headers=H(ANN), json={"role": "admin", "name": "Ann Driver"}).status_code == 200 and DB.users.find_one({"email": "ann@bkc.met.edu"}).get("role") != "admin")
pa = J(c.get("/api/profile", headers=H(ANN)))["user"]; pb = J(c.get("/api/profile", headers=H(BOB)))["user"]
check("driver profile shows rides_given=1 and rating 4.0", pa["rides_given"] == 1 and pa["avg_rating"] == 4.0, pa)
check("passenger profile shows rides_taken=1", pb["rides_taken"] == 1, pb)

print("\n== 5. Seats, reject, cancel ==")
r = c.post("/api/rides", headers=H(ANN), json={**ride_body, "seats_available": 1}); R2 = J(r)["ride"].get("id") or J(r)["ride"]["_id"]
c.post(f"/api/rides/{R2}/request", headers=H(BOB), json={"seats_requested": 1})
c.post(f"/api/rides/{R2}/request", headers=H(CAL), json={"seats_requested": 1})
check("accept first -> 200", c.post(f"/api/rides/{R2}/accept/{BOB_ID}", headers=H(ANN)).status_code == 200)
r = c.post(f"/api/rides/{R2}/accept/{CAL_ID}", headers=H(ANN))
check("no overbooking: second accept -> 409", r.status_code == 409, r.data[:150])
check("reject pending -> 200", c.post(f"/api/rides/{R2}/reject/{CAL_ID}", headers=H(ANN)).status_code == 200)
check("passenger cancels accepted booking -> 200", c.post(f"/api/rides/{R2}/cancel", headers=H(BOB), json={"reason": "plans changed"}).status_code == 200)
rd = DB.rides.find_one({"_id": __import__("bson").ObjectId(R2)})
check("seat restored and ride re-opened", rd["seats_available"] == 1 and rd["status"] == "PENDING", (rd["seats_available"], rd["status"]))
check("driver cancels whole ride -> 200", c.post(f"/api/rides/{R2}/cancel", headers=H(ANN), json={"reason": "car issue"}).status_code == 200)
r = c.post(f"/api/rides/{R2}/request", headers=H(BOB), json={"seats_requested": 1})
check("cannot request a cancelled ride -> 409", r.status_code == 409)

print("\n== 6. SOS, admin views, notifications ==")
r = c.post("/api/sos", headers=H(BOB), json={"latitude": 20.0, "longitude": 73.8, "message": "help"})
check("SOS -> 200", r.status_code == 200)
r = c.get("/api/admin/sos-alerts", headers=H(ADMIN)); al = J(r)["alerts"]
check("admin sees SOS alert", len(al) == 1 and al[0]["user_name"] == "Bob")
check("admin resolves SOS", c.post(f"/api/admin/sos-alerts/{al[0]['id']}/resolve", headers=H(ADMIN)).status_code == 200)
for st, expect in (("completed", 2), ("waiting", 0), ("active", 0)):
    r = c.get(f"/api/admin/rides?status={st}", headers=H(ADMIN))
    check(f"admin rides status={st} -> {expect}", r.status_code == 200 and J(r)["count"] == expect, J(r).get("count"))
r = c.post("/api/notifications/mark-all-read", headers=H(BOB)); check("mark all read", r.status_code == 200)
check("unread count is 0", J(c.get("/api/notifications", headers=H(BOB)))["unread_count"] == 0)
r = c.post(f"/api/admin/users/{CAL_ID}/block", headers=H(ADMIN)); check("admin blocks user", r.status_code == 200, r.data[:120])
check("blocked user's token rejected -> 403", c.get("/api/rides/my", headers=H(CAL)).status_code == 403)
check("blocked user cannot login -> 403", c.post("/api/login", json={"email": "cal@bkc.met.edu", "password": "Passw0rd!"}).status_code == 403)
check("admin unblocks", c.post(f"/api/admin/users/{CAL_ID}/unblock", headers=H(ADMIN)).status_code == 200)
check("unblocked user works again", c.get("/api/rides/my", headers=H(CAL)).status_code == 200)
check("no token -> 401", c.get("/api/rides/my").status_code == 401)

_up = app.config["UPLOAD_FOLDER"]
for f in os.listdir(_up):
    if f.startswith(("id_card_", "fee_receipt_")): os.remove(os.path.join(_up, f))   # tidy up test uploads
print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
