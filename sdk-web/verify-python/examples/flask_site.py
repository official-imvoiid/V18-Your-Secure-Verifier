"""
Smallest useful V18 website in Flask (example, see docs/web/INTEGRATION.md).

    pip install flask cryptography
    python examples/flask_site.py          # http://localhost:5000, V18 server at http://localhost:8080

The page has the 2-line embed. The server has the two V18 routes and keeps "is 18+" in Flask's
signed session cookie for one hour.
"""
import os
import sys
import time

from flask import Flask, abort, jsonify, redirect, request, session

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))  # use the local package
from v18_verify import ChallengeStore, V18Verifier  # noqa: E402

SITE_ORIGIN = os.environ.get("SITE_ORIGIN", "http://localhost:5000")  # exactly what the browser shows
V18_SERVER = os.environ.get("V18_SERVER_URL", "http://localhost:8080")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)  # set a fixed secret in real life
verifier = V18Verifier(server_url=V18_SERVER, origin=SITE_ORIGIN)
challenges = ChallengeStore()  # in memory: fine for one process (see INTEGRATION.md for several)


def visit_id() -> str:
    if "visit" not in session:
        session["visit"] = ChallengeStore.new_visit_id()
    return session["visit"]


@app.before_request
def refuse_cross_site_posts():
    if request.method == "POST" and request.headers.get("Origin") not in (None, SITE_ORIGIN):
        abort(403)


@app.post("/v18/challenge")
def v18_challenge():
    return jsonify(challenges.create(visit_id()).to_dict())


@app.post("/v18/verify")
def v18_verify():
    ticket = (request.get_json(silent=True) or {}).get("ticket")
    result = verifier.verify_ticket(ticket, expected_challenge=challenges.checker(visit_id()), min_age=18)
    if not result.valid:
        return jsonify(ok=False, code=result.code, error=result.error), 403
    session["adult_until"] = int(time.time()) + 3600
    return jsonify(ok=True, minAge=result.ticket.min_age)


def is_adult() -> bool:
    return session.get("adult_until", 0) > time.time()


@app.get("/")
def home():
    if is_adult():
        return redirect("/members")
    return f"""<!doctype html><title>Example</title><h1>This site is for adults</h1>
<script src="/v18.js" data-v18-server="{V18_SERVER}"></script>
<button data-v18-min-age="18" data-v18-redirect="/members">Verify age</button>"""


@app.get("/v18.js")
def widget_script():
    # In real life this comes from V18's CDN. Here: the bundle built in sdk-web/widget.
    from flask import send_file
    return send_file(os.path.join(os.path.dirname(__file__), "..", "..", "widget", "dist", "v18.js"),
                     mimetype="text/javascript")


@app.get("/members")
def members():
    if not is_adult():
        return redirect("/")
    return "<h1>Welcome in</h1><p>This site only learned one thing: 18+.</p>"


if __name__ == "__main__":
    app.run(port=5000)
