from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from html import escape
from http.cookies import SimpleCookie
from pathlib import Path
import sqlite3
import hashlib
import secrets
import hmac
import time
from datetime import datetime, timezone

ROOT = Path(__file__).parent
tietokanta = ROOT / "notes.db"

SESSIONS = {}
# fix 5: track failed loggings
# väärät_kirjautumiset = {}

# fix 4: track logging
# kirjautumiset = {}


def yhdistä():
    yhteys = sqlite3.connect(tietokanta)
    yhteys.row_factory = sqlite3.Row
    return yhteys



def hash_salasana(password, salt):

    # flaw 2: Cryptographic Failures
    return password.encode("utf-8")

    # fiz 2: Hash passwords
    # return hashlib.pbkdf2_hmac(
    #     "sha256",
    #     password.encode("utf-8"),
    #     salt,
    #     200_000
    # )



def init_db():
    with yhdistä() as db:

        db.execute('''
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                body TEXT NOT NULL
            )
        ''')

        kolumnit = [
            rivi["name"]
            for rivi in db.execute("PRAGMA table_info(notes)")
        ]

        if "owner" not in kolumnit:
            db.execute(
                "ALTER TABLE notes ADD COLUMN owner TEXT"
            )

        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL
            )
        ''')

        käyttäjät = [
            ("pentti", "123"),
            ("matti", "321")
        ]

        for username, password in käyttäjät:
            user = db.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if user is None:
                salt = secrets.token_bytes(16)
                tallennettu_salasana = hash_salasana(password, salt)

                db.execute(
                    "INSERT INTO users "
                    "(username, salt, password_hash) "
                    "VALUES (?, ?, ?)",
                    (username, salt, tallennettu_salasana)
                )


def sivu(notes):
    rivit = ''.join(
        f'<article>'
        f'<h2><a href="/note/{rivi["id"]}">{escape(rivi["title"])}</a></h2>'
        f'<p>{escape(rivi["body"])}</p>'
        f'</article>'
        for rivi in notes
    )

    template = (
        ROOT / "templates" / "index.html"
    ).read_text(encoding="utf-8")

    return template.replace(
        "<!-- NOTES -->",
        rivit or "<p>Ei muistiinpanoja vielä.</p>"
    )


class Handler(BaseHTTPRequestHandler):

    def token(self):
        cookies = SimpleCookie()

        try:
            cookies.load(self.headers.get("Cookie", ""))
        except Exception:
            return None

        if "session" in cookies:
            return cookies["session"].value

        return None

    def nykyinen_käyttäjä(self):
        return SESSIONS.get(self.token())

    def redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header("Location", location)

        if cookie:
            self.send_header("Set-Cookie", cookie)

        self.end_headers()

    def do_GET(self):

        if self.path == "/login":
            html = (
                ROOT / "templates" / "login.html"
            ).read_text(encoding="utf-8")

            return self.respond(html)

        if self.path == "/":
            if not self.nykyinen_käyttäjä():
                return self.redirect("/login")

            with yhdistä() as tietokanta:
                items = tietokanta.execute(
                    "SELECT id, title, body FROM notes "
                    "WHERE owner = ? ORDER BY id DESC",
                    (self.nykyinen_käyttäjä(),)
                ).fetchall()

            return self.respond(sivu(items))
        
        
        # flaw 3: SQL Injection
        if self.path == "/search" or self.path.startswith("/search?"):

            if not self.nykyinen_käyttäjä():
                return self.redirect("/login")

            search = parse_qs(
                self.path.partition("?")[2]
            ).get("q", [""])[0]

            with yhdistä() as tietokanta:

                sql = (
                    "SELECT id, title, body FROM notes "
                    "WHERE owner = ? AND title LIKE '%" + search + "%' "
                    "ORDER BY id DESC"
                )

                items = tietokanta.execute(
                    sql, (self.nykyinen_käyttäjä(),)
                ).fetchall()

                # fix 3: fixed SQL-query
                # items = tietokanta.execute(
                #     "SELECT id, title, body FROM notes "
                #     "WHERE owner = ? AND title LIKE ? "
                #     "ORDER BY id DESC",
                #     (self.nykyinen_käyttäjä(), f"%{search}%")
                # ).fetchall()

            return self.respond(sivu(items))
        
        if self.path.startswith("/note/"):

            if not self.nykyinen_käyttäjä():
                return self.redirect("/login")
            try:
                note_id = int(self.path.split("/")[-1])
            except ValueError:
                return self.send_error(400)

            # flaw 1: Broken Access Control
            with yhdistä() as tietokanta:
                muistiinpano = tietokanta.execute(
                    "SELECT id, title, body, owner "
                    "FROM notes WHERE id = ?",
                    (note_id,)
                ).fetchone()

            # fix 1: check note owner
            # with yhdistä() as tietokanta:
            #     muistiinpano = tietokanta.execute(
            #         "SELECT id, title, body, owner "
            #         "FROM notes WHERE id = ? AND owner = ?",
            #         (note_id, self.nykyinen_käyttäjä())
            #     ).fetchone()

            if muistiinpano is None:
                return self.send_error(404)

            html = (
                f'<h1>{escape(muistiinpano["title"])}</h1>'
                f'<p>{escape(muistiinpano["body"])}</p>'
                '<a href="/">Takaisin</a>'
            )

            return self.respond(html)

        self.send_error(404)

    def do_POST(self):

        if self.path not in ("/login", "/new", "/logout"):
            return self.send_error(404)

        length = int(self.headers.get("Content-Length", "0"))

        if length > 10000 or length < 0:
            return self.send_error(413)

        fields = parse_qs(
            self.rfile.read(length).decode("utf-8")
        )

        if self.path == "/login":
            username = fields.get("username", [""])[0]
            password = fields.get("password", [""])[0]

            # flaw 4: Identification and Authentication Failures

            # fix 4: check logging attemps
            # ip = self.client_address[0]
            # attempts, blocked_until = kirjautumiset.get(ip, (0, 0))
            
            # if blocked_until > time.monotonic():
            #     return self.respond(
            #         "<h1>Liikaa kirjautumisyrityksiä.</h1>",
            #         429
            #     )
            
            # if blocked_until:
            #     kirjautumiset.pop(ip, None)

            with yhdistä() as tietokanta:
                user = tietokanta.execute(
                    "SELECT salt, password_hash "
                    "FROM users WHERE username = ?",
                    (username,)
                ).fetchone()

            if user and hmac.compare_digest(
                hash_salasana(password, user["salt"]),
                user["password_hash"]
            ):

                # fix 4: reset attempts
                # kirjautumiset.pop(ip, None)

                token = secrets.token_urlsafe(32)
                SESSIONS[token] = username

                return self.redirect(
                    "/",
                    f"session={token}; HttpOnly; SameSite=Lax; Path=/"
                )

            # fix 4: count failed loggings
            # attempts, _ = kirjautumiset.get(ip, (0, 0))
            # attempts += 1
            
            # if attempts >= 5:
            #     kirjautumiset[ip] = (
            #         attempts,
            #         time.monotonic() + 60
            #     )
            # else:
            #     kirjautumiset[ip] = (attempts, 0)


            # flaw 5: Security Logging and Monitoring Failures

            # fix 5: log failed attempst
            # key = (username, self.client_address[0])
            # väärät_kirjautumiset[key] = väärät_kirjautumiset.get(key, 0) + 1
            
            # timestamp = datetime.now(timezone.utc).isoformat()
            
            # with (ROOT / "security.log").open("a", encoding="utf-8") as log:
            #     log.write(
            #         f"{timestamp} LOGIN_FAILED "
            #         f"user={username!r} ip={key[1]}\n"
            #     )
            
            #     if väärät_kirjautumiset[key] == 3:
            #         log.write(
            #             f"{timestamp} WARNING "
            #             f"Repeated failed logins for {username!r}\n"
            #          )

            html = (
                ROOT / "templates" / "login.html"
            ).read_text(encoding="utf-8")

            html = html.replace(
                "<!-- ERROR -->",
                "<p>Väärä käyttäjätunnus tai salasana.</p>"
            )

            return self.respond(html, 401)

        if self.path == "/logout":
            SESSIONS.pop(self.token(), None)

            return self.redirect(
                "/login",
                "session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/"
            )

        if not self.nykyinen_käyttäjä():
            return self.redirect("/login")

        otsikko = fields.get("title", [""])[0].strip()
        sisältö = fields.get("body", [""])[0].strip()

        if otsikko and sisältö:
            with yhdistä() as tietokanta:
                tietokanta.execute(
                    "INSERT INTO notes (title, body, owner) "
                    "VALUES (?, ?, ?)",
                    (otsikko, sisältö, self.nykyinen_käyttäjä())
                )

        return self.redirect("/")

    def respond(self, html, status=200):
        data = html.encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    init_db()

    server = HTTPServer(
        ("127.0.0.1", 8000),
        Handler
    )

    server.serve_forever()