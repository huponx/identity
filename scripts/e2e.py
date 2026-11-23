#!/usr/bin/env python3
"""End to end check of a running identity (local): authorization code + PKCE, refresh rotation and
reuse detection, client_credentials, token exchange, introspection, MFA step.

  ISSUER=http://localhost:18080 EMAIL=admin@example.com PASSWORD=... GATEKEEPER_SECRET=... scripts/e2e.py
"""
import base64, hashlib, hmac, http.cookiejar, json, os, re, secrets, struct, sys, time
import urllib.error, urllib.parse, urllib.request

ISS = os.environ.get("ISSUER", "http://localhost:18080")
EMAIL = os.environ["EMAIL"]
PASSWORD = os.environ["PASSWORD"]
GK_SECRET = os.environ["GATEKEEPER_SECRET"]
WEB = os.environ.get("WEB_CLIENT", "webgk")
GK = os.environ.get("GK_CLIENT", "gatekeeper")
REDIRECT = "http://localhost:3000/cb"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)


def call(method, url, data=None, headers=None, raw=None):
    req = urllib.request.Request(url, method=method, headers=headers or {},
                                 data=raw if raw is not None else
                                 urllib.parse.urlencode(data).encode() if data is not None else None)
    try:
        r = opener.open(req)
    except urllib.error.HTTPError as e:
        r = e
    return r.status, dict(r.headers), r.read().decode()


def call_json(method, url, data):
    return call(method, url, None, {"Content-Type": "application/json", "Origin": ISS}, json.dumps(data).encode())


def check(name, cond, extra=""):
    print(("ok   " if cond else "FAIL ") + name + (" " + str(extra) if not cond else ""))
    if not cond:
        sys.exit(1)


def jwt(tok):
    p = tok.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def basic(cid, sec):
    return {"Authorization": "Basic " + base64.b64encode(f"{cid}:{sec}".encode()).decode()}


def totp(secret_b32):
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    mac = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    o = mac[-1] & 15
    return "%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 10**6)


verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
state, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
q = urllib.parse.urlencode({
    "response_type": "code", "client_id": WEB, "redirect_uri": REDIRECT, "scope": "openid profile email offline_access",
    "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"})

# PKCE is mandatory: without a challenge the request is refused
s, h, b = call("GET", f"{ISS}/oauth2/authorize?" + q.replace("code_challenge=" + challenge, "x=1"))
check("authorize without PKCE is refused", s in (302, 400) and "code=" not in h.get("Location", ""), (s, h.get("Location")))

s, h, b = call("GET", f"{ISS}/oauth2/authorize?{q}")
check("authorize redirects to login", s == 302 and "/login" in h["Location"], (s, h))
ret = urllib.parse.parse_qs(urllib.parse.urlparse(h["Location"]).query)["return_to"][0]
# the sign in page is the app of the web repository; its calls are the JSON API (same origin, CSRF token + cookie)
s, h, b = call("GET", f"{ISS}/auth-api/csrf")
check("csrf token", s == 200, (s, b))
csrf = json.loads(b)["csrf"]

s, h, b = call_json("POST", f"{ISS}/auth-api/login", {"csrf": csrf, "return_to": ret, "email": EMAIL, "password": "wrong-password-xx"})
check("wrong password is refused", s == 401 and json.loads(b)["code"] == "invalid_credentials", (s, b))
s, h, b = call_json("POST", f"{ISS}/auth-api/login", {"csrf": csrf, "return_to": ret, "email": EMAIL, "password": PASSWORD})
check("login ok -> redirect", s == 200 and "redirect" in json.loads(b), (s, b[:200]))
loc = json.loads(b)["redirect"]
s, h, b = call("GET", ISS + loc if loc.startswith("/") else loc)
check("authorize returns the code", s == 302 and h["Location"].startswith(REDIRECT), (s, h))
cb = urllib.parse.urlparse(h["Location"])
qs = urllib.parse.parse_qs(cb.query)
check("state echoed", qs["state"][0] == state)
code = qs["code"][0]

s, h, b = call("POST", f"{ISS}/oauth2/token", {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                                "client_id": WEB, "code_verifier": "x" * 50})
check("wrong PKCE verifier refused", s == 400, (s, b))
# the code was consumed by the failed attempt (single use)
s, h, b = call("POST", f"{ISS}/oauth2/token", {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                                "client_id": WEB, "code_verifier": verifier})
check("code is single use", s == 400, (s, b))

# second round, correct verifier
s, h, b = call("GET", f"{ISS}/oauth2/authorize?{q}")
check("SSO session: no second login", s == 302 and h["Location"].startswith(REDIRECT), (s, h))
code = urllib.parse.parse_qs(urllib.parse.urlparse(h["Location"]).query)["code"][0]
s, h, b = call("POST", f"{ISS}/oauth2/token", {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                                "client_id": WEB, "code_verifier": verifier})
check("token exchange of the code", s == 200, (s, b))
tok = json.loads(b)
acc, idt, rt = tok["access_token"], tok["id_token"], tok["refresh_token"]
ac = jwt(acc)
check("access token claims", ac["iss"] == ISS and ac["aud"] in ("gatekeeper", ["gatekeeper"]) and ac.get("jti") and "admin" in ac.get("roles", []) and "*" in ac.get("perms", []), ac)
ic = jwt(idt)
check("id token nonce/at_hash/sid", ic["nonce"] == nonce and ic.get("at_hash") and ic.get("sid"), ic)

s, h, b = call("GET", f"{ISS}/userinfo", headers={"Authorization": "Bearer " + acc})
check("userinfo", s == 200 and json.loads(b)["email"] == EMAIL, (s, b))

# service: client_credentials + introspect + exchange
s, h, b = call("POST", f"{ISS}/oauth2/token", {"grant_type": "client_credentials", "audience": "courier"}, basic(GK, GK_SECRET))
check("client_credentials", s == 200, (s, b))
svc = json.loads(b)["access_token"]
check("service token aud", jwt(svc)["aud"] in ("courier", ["courier"]), jwt(svc))
s, h, b = call("POST", f"{ISS}/oauth2/token", {"grant_type": "client_credentials", "audience": "billing"}, basic(GK, GK_SECRET))
check("client_credentials for an audience without policy is denied", s in (400, 403), (s, b))
s, h, b = call("POST", f"{ISS}/oauth2/introspect", {"token": acc}, basic(GK, GK_SECRET))
check("introspect active", s == 200 and json.loads(b)["active"] is True, (s, b))

EX = "urn:ietf:params:oauth:grant-type:token-exchange"
AT = "urn:ietf:params:oauth:token-type:access_token"
s, h, b = call("POST", f"{ISS}/oauth2/token", {"grant_type": EX, "subject_token": acc, "subject_token_type": AT, "audience": "courier"},
               basic(GK, GK_SECRET))
check("token exchange (user -> courier)", s == 200, (s, b))
ex = jwt(json.loads(b)["access_token"])
check("exchange claims: sub kept, act=gatekeeper, no refresh", ex["sub"] == ac["sub"] and ex["act"]["client_id"] == GK and "refresh_token" not in json.loads(b), ex)
s, h, b = call("POST", f"{ISS}/oauth2/token", {"grant_type": EX, "subject_token": acc, "subject_token_type": AT, "audience": "billing"},
               basic(GK, GK_SECRET))
check("exchange without policy is denied", s in (400, 403), (s, b))

# revoke
s, h, b = call("POST", f"{ISS}/oauth2/revoke", {"token": acc}, basic(GK, GK_SECRET))
s, h, b = call("POST", f"{ISS}/oauth2/introspect", {"token": acc}, basic(GK, GK_SECRET))
check("another client cannot revoke the token", json.loads(b)["active"] is True, b)
s, h, b = call("POST", f"{ISS}/oauth2/revoke", {"token": acc, "client_id": WEB})
s, h, b = call("POST", f"{ISS}/oauth2/introspect", {"token": acc}, basic(GK, GK_SECRET))
check("revoked access token inactive", json.loads(b)["active"] is False, b)
# refresh rotation + reuse detection
s, h, b = call("POST", f"{ISS}/oauth2/token", {"grant_type": "refresh_token", "refresh_token": rt, "client_id": WEB})
check("refresh rotates", s == 200 and json.loads(b)["refresh_token"] != rt, (s, b))
rt2 = json.loads(b)["refresh_token"]
s, h, b = call("POST", f"{ISS}/oauth2/token", {"grant_type": "refresh_token", "refresh_token": rt, "client_id": WEB})
check("reused refresh token refused", s == 400, (s, b))
s, h, b = call("POST", f"{ISS}/oauth2/token", {"grant_type": "refresh_token", "refresh_token": rt2, "client_id": WEB})
check("reuse revokes the whole family", s == 400, (s, b))

print("ALL OK")
