from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session, Response,
    stream_with_context
)
import smtplib
import ssl
import re
import os
import json
import urllib.request
import urllib.parse
import secrets
import random

from email.mime.text import MIMEText
from email.utils import formataddr
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static"
)


app.secret_key = os.environ.get(
    "SESSION_SECRET",
    ""
)


MAX_RECIPIENTS = 25

TURNSTILE_SECRET_KEY = os.environ.get(
    "TURNSTILE_SECRET_KEY",
    ""
)


EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    return bool(
        EMAIL_RE.fullmatch(
            value.strip()
        )
    )


def authenticated():
    return session.get(
        "authenticated"
    ) is True


# =========================================================
# SPINTAX - ALWAYS ON
# =========================================================

SPINTAX_RE = re.compile(
    r"\{([^{}]+)\}"
)


def expand_spintax(text):

    def replace_match(match):

        options = [
            option.strip()
            for option in match.group(1).split("|")
            if option.strip()
        ]

        if len(options) < 2:
            return match.group(0)

        return random.choice(options)

    return SPINTAX_RE.sub(
        replace_match,
        text
    )


# =========================================================
# TURNSTILE
# =========================================================

def verify_turnstile(token, remote_ip=None):

    if not TURNSTILE_SECRET_KEY:
        return (
            False,
            "TURNSTILE_SECRET_KEY is not configured."
        )

    if not token:
        return (
            False,
            "Cloudflare verification is required."
        )

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(
        payload
    ).encode("utf-8")

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={
            "Content-Type":
            "application/x-www-form-urlencoded"
        },
        method="POST"
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=10
        ) as response:

            result = json.loads(
                response.read().decode("utf-8")
            )

        if result.get("success") is True:
            return True, None

        return (
            False,
            "Cloudflare verification failed."
        )

    except Exception:

        return (
            False,
            "Unable to verify Cloudflare."
        )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if authenticated():
        return redirect(
            url_for("home")
        )

    error = None

    if request.method == "POST":

        password = str(
            request.form.get(
                "password",
                ""
            )
        )

        configured_password = os.environ.get(
            "LOGIN_PASSWORD",
            ""
        )

        if not configured_password:

            error = (
                "LOGIN_PASSWORD is not configured."
            )

        elif secrets.compare_digest(
            password,
            configured_password
        ):

            session["authenticated"] = True

            return redirect(
                url_for("home")
            )

        else:

            error = "Incorrect password."

    return render_template(
        "login.html",
        error=error
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if not authenticated():

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html",
        turnstile_site_key=os.environ.get(
            "TURNSTILE_SITE_KEY",
            ""
        )
    )


# =========================================================
# SEND BATCH
# =========================================================

@app.route(
    "/send-batch",
    methods=["POST"]
)
def send_batch():

    if not authenticated():

        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401


    data = request.get_json(
        silent=True
    ) or {}


    sender_name = str(
        data.get(
            "sender_name",
            ""
        )
    ).strip()


    gmail = str(
        data.get(
            "gmail",
            ""
        )
    ).strip()


    app_password = str(
        data.get(
            "app_password",
            ""
        )
    ).strip()


    subject = str(
        data.get(
            "subject",
            ""
        )
    ).strip()


    body = str(
        data.get(
            "body",
            ""
        )
    )


    is_html = bool(
        data.get(
            "is_html",
            False
        )
    )


    recipients = data.get(
        "recipients",
        []
    )


    turnstile_token = str(
        data.get(
            "turnstile_token",
            ""
        )
    ).strip()


    if not sender_name:

        return jsonify({
            "success": False,
            "message": "Sender Name is required."
        }), 400


    if not valid_email(gmail):

        return jsonify({
            "success": False,
            "message": "Enter a valid Gmail address."
        }), 400


    if not app_password:

        return jsonify({
            "success": False,
            "message": "Google App Password is required."
        }), 400


    if not subject:

        return jsonify({
            "success": False,
            "message": "Email subject is required."
        }), 400


    if not body.strip():

        return jsonify({
            "success": False,
            "message": "Message body is required."
        }), 400


    if not isinstance(
        recipients,
        list
    ):

        return jsonify({
            "success": False,
            "message": "Invalid recipient list."
        }), 400


    clean_recipients = []


    for item in recipients:

        email = str(
            item
        ).strip().lower()


        if not valid_email(email):
            continue


        if email not in clean_recipients:

            clean_recipients.append(
                email
            )


    clean_recipients = clean_recipients[
        :MAX_RECIPIENTS
    ]


    if not clean_recipients:

        return jsonify({
            "success": False,
            "message": "No valid recipients found."
        }), 400


    verified, verify_error = verify_turnstile(
        turnstile_token,
        request.headers.get(
            "X-Forwarded-For",
            request.remote_addr
        )
    )


    if not verified:

        return jsonify({
            "success": False,
            "message": verify_error
        }), 403


    @stream_with_context
    def generate():

        total = len(
            clean_recipients
        )

        sent_count = 0
        failed_count = 0
        remaining = total


        yield (
            json.dumps({
                "type": "start",
                "total": total,
                "sent": 0,
                "failed": 0,
                "remaining": total
            }) + "\n"
        )


        context = ssl.create_default_context()


        try:

            with smtplib.SMTP_SSL(
                "smtp.gmail.com",
                465,
                context=context,
                timeout=15
            ) as server:


                server.login(
                    gmail,
                    app_password
                )


                for recipient in clean_recipients:

                    try:

                        # Spintax permanently ON
                        final_subject = expand_spintax(
                            subject
                        )

                        final_body = expand_spintax(
                            body
                        )


                        content_type = (
                            "html"
                            if is_html
                            else "plain"
                        )


                        message = MIMEText(
                            final_body,
                            content_type,
                            "utf-8"
                        )


                        message["Subject"] = (
                            final_subject
                        )


                        message["From"] = formataddr(
                            (
                                sender_name,
                                gmail
                            )
                        )


                        message["To"] = recipient


                        server.sendmail(
                            gmail,
                            [recipient],
                            message.as_string()
                        )


                        sent_count += 1
                        remaining -= 1


                        yield (
                            json.dumps({
                                "type": "progress",
                                "email": recipient,
                                "result": "sent",
                                "total": total,
                                "sent": sent_count,
                                "failed": failed_count,
                                "remaining": remaining
                            }) + "\n"
                        )


                    except Exception as exc:

                        failed_count += 1
                        remaining -= 1


                        yield (
                            json.dumps({
                                "type": "progress",
                                "email": recipient,
                                "result": "failed",
                                "error": str(exc),
                                "total": total,
                                "sent": sent_count,
                                "failed": failed_count,
                                "remaining": remaining
                            }) + "\n"
                        )


        except smtplib.SMTPAuthenticationError:

            yield (
                json.dumps({
                    "type": "error",
                    "message":
                    "Gmail authentication failed. Check Gmail and App Password.",
                    "total": total,
                    "sent": sent_count,
                    "failed": failed_count,
                    "remaining": remaining
                }) + "\n"
            )

            return


        except smtplib.SMTPException as exc:

            yield (
                json.dumps({
                    "type": "error",
                    "message":
                    f"SMTP connection error: {str(exc)}",
                    "total": total,
                    "sent": sent_count,
                    "failed": failed_count,
                    "remaining": remaining
                }) + "\n"
            )

            return


        except Exception as exc:

            yield (
                json.dumps({
                    "type": "error",
                    "message":
                    f"Server error: {str(exc)}",
                    "total": total,
                    "sent": sent_count,
                    "failed": failed_count,
                    "remaining": remaining
                }) + "\n"
            )

            return


        yield (
            json.dumps({
                "type": "complete",
                "success": True,
                "message":
                "sending compleate Babu❤️",
                "total": total,
                "sent": sent_count,
                "failed": failed_count,
                "remaining": remaining
            }) + "\n"
        )


    return Response(
        generate(),
        content_type=(
            "application/x-ndjson; charset=utf-8"
        ),
        headers={
            "Cache-Control":
            "no-cache, no-transform",
            "X-Accel-Buffering":
            "no"
        }
    )


# =========================================================
# HEALTH
# =========================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "Secure Mail Console",
        "mailer": "Gmail SMTP",
        "spintax": "always_on"
    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
