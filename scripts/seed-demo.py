#!/usr/bin/env python3
"""Fills a fresh GateKeeper database with plausible demo data for screenshots.

Run it against a database that GateKeeper has already created and migrated, with
the server stopped. It writes cookies.json holding a signed in user session and
an admin session, which scripts/screenshots.mjs reads.

    python3 scripts/seed-demo.py /path/to/gatekeeper.db
"""

import hashlib
import json
import secrets
import sqlite3
import sys
import time
import uuid

DAY = 86400


def main(db_path: str, cookie_path: str = "cookies.json") -> None:
    conn = sqlite3.connect(db_path)
    now = int(time.time())

    admin_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO admin_users (id,email,password_hash,created_at,display_name,api_key)"
        " VALUES (?,?,?,?,?,?)",
        (admin_id, "admin@example.com", "x", now - 90 * DAY, "Alex Morgan", ""),
    )
    admin_session = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO admin_sessions (id,admin_id,created_at,expires_at) VALUES (?,?,?,?)",
        (admin_session, admin_id, now, now + 8 * 3600),
    )

    people = [
        ("Sarah Chen", "sarah@example.com", 1),
        ("Marcus Webb", "marcus@example.com", 1),
        ("Priya Nair", "priya@example.com", 0),
        ("Tom Okafor", "tom@example.com", 1),
        ("Lena Fischer", "lena@example.com", 0),
        ("Diego Ramos", "diego@example.com", 1),
    ]
    user_ids = []
    for i, (name, email, totp) in enumerate(people):
        uid = str(uuid.uuid4())
        user_ids.append(uid)
        conn.execute(
            "INSERT INTO users (id,email,password_hash,created_at,updated_at,display_name,"
            "totp_enabled,disabled,email_verified) VALUES (?,?,?,?,?,?,?,0,1)",
            (uid, email, "x", now - (60 - i * 7) * DAY, now - i * DAY, name, totp),
        )

    raw = secrets.token_hex(32)
    session_id = hashlib.sha256(raw.encode()).hexdigest()
    data = json.dumps(
        {
            "UserID": user_ids[0],
            "PendingOTP": False,
            "PendingTOTP": False,
            "RedirectURI": "",
            "OIDCRequestID": "",
        }
    )
    devices = [
        ("203.0.113.42", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"),
        ("198.51.100.17", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1 Safari/604.1"),
    ]
    for i, (ip, ua) in enumerate(devices):
        sid = session_id if i == 0 else hashlib.sha256(secrets.token_hex(32).encode()).hexdigest()
        conn.execute(
            "INSERT INTO sessions (id,user_id,data,created_at,expires_at,last_seen,ip,user_agent)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (sid, user_ids[0], data, now - i * 3600, now + DAY, now - i * 1800, ip, ua),
        )

    groups = [
        ("Engineering", "Full access to internal tooling", user_ids[:3]),
        ("Media", "Jellyfin and media apps", user_ids[2:5]),
        ("Admins", "Infrastructure administrators", user_ids[:1]),
    ]
    for name, desc, members in groups:
        gid = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO groups (id,name,description,created_at) VALUES (?,?,?,?)",
            (gid, name, desc, now - 30 * DAY),
        )
        for member in members:
            conn.execute("INSERT INTO group_members (group_id,user_id) VALUES (?,?)", (gid, member))

    policies = [
        ("internal-tools", "Staff-only internal applications"),
        ("media", "Media library access"),
        ("admins", "Infrastructure dashboards"),
    ]
    policy_ids = {}
    for name, desc in policies:
        pid = str(uuid.uuid4())
        policy_ids[name] = pid
        conn.execute(
            "INSERT INTO policies (id,name,description,created_at) VALUES (?,?,?,?)",
            (pid, name, desc, now - 25 * DAY),
        )
        for member in user_ids[:3]:
            conn.execute(
                "INSERT INTO policy_members (policy_id,user_id) VALUES (?,?)", (pid, member)
            )

    clients = [
        ("Grafana", "grafana", "internal-tools"),
        ("Jellyfin", "jellyfin", "media"),
        ("Immich", "immich", "media"),
        ("Traefik Manager", "traefik-manager", "admins"),
    ]
    for name, cid, policy in clients:
        uris = [f"https://{cid}.example.com/oauth/callback"]
        if cid == "immich":
            uris = [
                "https://immich.example.com/auth/login",
                "https://immich.example.com/user-settings",
                "app.immich:///oauth-callback",
            ]
        conn.execute(
            "INSERT INTO oidc_clients (id,client_id,client_secret,redirect_uris,name,created_at,"
            "policy_id,credentials_scopes) VALUES (?,?,?,?,?,?,?,'')",
            (str(uuid.uuid4()), cid, "secret", json.dumps(uris), name, now - 40 * DAY,
             policy_ids.get(policy, "")),
        )

    conn.execute(
        "INSERT INTO webhooks (id,name,type,enabled,url,token,chat_id,username,password,topic,"
        "events,created_at) VALUES (?,?,?,1,?,'','','','','',?,?)",
        (str(uuid.uuid4()), "Ops Discord", "discord",
         "https://discord.com/api/webhooks/redacted",
         json.dumps(["login.failure", "admin.login"]), now - 20 * DAY),
    )

    conn.execute(
        "INSERT INTO invites (id,token_hash,email,note,created_by,expires_at,created_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), hashlib.sha256(b"tok").hexdigest(), "newhire@example.com",
         "Onboarding", admin_id, now + 7 * DAY, now - 2 * DAY),
    )

    events = [
        ("login.success", 0), ("login.success", 1), ("login.passkey", 2),
        ("otp.verified", 0), ("login.failure", None), ("admin.login", None),
        ("user.created", 3), ("totp.enrolled", 1), ("login.success", 4),
        ("group.member_added", 2), ("client.created", None), ("login.social", 5),
        ("session.revoked", 0), ("login.success", 3), ("backup.created", None),
    ]
    for i, (event, who) in enumerate(events):
        for day in range(7):
            conn.execute(
                "INSERT INTO audit_log (id,event,user_id,actor_id,ip,detail,created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), event,
                 user_ids[who] if who is not None else None,
                 admin_id if event.startswith("admin") else None,
                 f"203.0.113.{20 + i}",
                 "wrong password" if event == "login.failure" else "",
                 now - day * DAY - i * 1800),
            )

    conn.commit()
    conn.close()

    with open(cookie_path, "w") as fh:
        json.dump({"user": raw, "admin": admin_session}, fh)
    print(f"seeded {db_path}, cookies written to {cookie_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    main(*sys.argv[1:])
