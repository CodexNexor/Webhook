#!/usr/bin/env python3
"""
Multi-bot Telegram webhook server.

Features:
- Register many bots via POST /register_bot (admin-only). Each bot gets a bot_key.
- Set each bot's Telegram webhook to: https://<domain>/webhook/<bot_key>
- Incoming updates to /webhook/<bot_key> are replied to using that bot's token.
- Token mapping persisted to bot_tokens.json (file mode 600).
- Admin endpoints: /register_bot, /delete_bot, /list_bots
- Debug endpoints: /token_status/<bot_key>, /test, /health
"""

import os
import json
import logging
import stat
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote
import threading
import requests

# Config
TOKENS_FILE = "bot_tokens.json"
ADMIN_SECRET_ENV = "ADMIN_SECRET"   # must be set in Railway variables (recommended)
REQUEST_TIMEOUT = 10               # seconds for Telegram API calls
IMAGE_URL = "static/token.jpg"     # change to public https url to send photos
MESSAGE_TEXT = """Hello! This is an automated reply. Send /help for commands."""
FILE_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0o600

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("multi-webhook")

# Helper: persist token mapping
def load_tokens():
    if os.path.exists(TOKENS_FILE):
        try:
            with open(TOKENS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {k: v for k, v in data.items() if v}
        except Exception as e:
            logger.exception("Failed to load tokens file: %s", e)
            return {}
    return {}

def save_tokens(mapping):
    try:
        with open(TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(mapping, f, indent=2)
        try:
            os.chmod(TOKENS_FILE, FILE_MODE)
        except Exception:
            logger.warning("Could not chmod tokens file")
    except Exception as e:
        logger.exception("Failed to save tokens file: %s", e)

# Load tokens at startup
BOT_TOKENS = load_tokens()

def set_bot_token(bot_key, token):
    BOT_TOKENS[bot_key] = token.strip()
    save_tokens(BOT_TOKENS)
    logger.info("Set token for bot_key=%s", bot_key)

def delete_bot_token(bot_key):
    if bot_key in BOT_TOKENS:
        BOT_TOKENS.pop(bot_key, None)
        save_tokens(BOT_TOKENS)
        logger.info("Deleted token for bot_key=%s", bot_key)
        return True
    return False

def get_bot_token(bot_key):
    return BOT_TOKENS.get(bot_key)

def list_bot_keys():
    return list(BOT_TOKENS.keys())

# Telegram API helper
def telegram_api_call(token, method, payload):
    url = f"https://api.telegram.org/bot{token}/{method}"
    r = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    try:
        body = r.json()
    except Exception:
        body = r.text
    logger.info("Telegram API %s (bot_key?) response status=%s body=%s", method, r.status_code, body)
    return r.status_code, body

# HTTP Handler
class MultiBotHandler(BaseHTTPRequestHandler):
    def _send_json(self, obj, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except Exception:
            length = 0
        if length <= 0:
            return None
        raw = self.rfile.read(length)
        try:
            text = raw.decode("utf-8")
        except Exception:
            text = raw.decode("latin1", errors="replace")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            token_status = {k: True for k in list_bot_keys()}
            html = f"""
            <html>
              <body style="font-family:Arial,sans-serif;padding:20px;">
                <h2>Multi-bot Telegram Webhook Server</h2>
                <p>Registered bots: {len(token_status)}</p>
                <ul>{"".join(f"<li>{k}</li>" for k in token_status.keys())}</ul>
                <p>Register a bot (admin-only): POST /register_bot JSON: {{'bot_key':'bot1','token':'...','admin_secret':'...'}} </p>
                <p>Set Telegram webhook for each bot to: <code>https://&lt;your-domain&gt;/webhook/&lt;bot_key&gt;</code></p>
                <p>Health: <a href="/health">/health</a> | Test: <a href="/test">/test</a></p>
              </body>
            </html>
            """
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode())
            return

        if path == "/health":
            self._send_json({"status": "healthy", "registered_bots": len(list_bot_keys())})

        elif path == "/test":
            self._send_json({"status": "ok", "registered_bots": len(list_bot_keys())})

        elif path.startswith("/token_status/"):
            # /token_status/<bot_key>
            bot_key = unquote(path.split("/token_status/", 1)[1])
            exists = bool(get_bot_token(bot_key))
            self._send_json({"bot_key": bot_key, "token_set": exists})

        elif path == "/list_bots":
            # optional public list (admin-only better, but read-only)
            self._send_json({"bots": list_bot_keys()})

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/register_bot":
            body = self._read_json_body()
            if not body:
                return self._send_json({"error": "missing JSON body"}, status=400)
            bot_key = body.get("bot_key")
            token = body.get("token")
            admin_secret = body.get("admin_secret")
            if not bot_key or not token:
                return self._send_json({"error": "bot_key and token required"}, status=400)
            # admin check
            required = os.environ.get(ADMIN_SECRET_ENV)
            if required:
                if admin_secret != required:
                    logger.warning("Unauthorized register attempt from %s", self.client_address)
                    return self._send_json({"error": "invalid admin_secret"}, status=401)
            set_bot_token(bot_key, token)
            return self._send_json({"status": "ok", "bot_key": bot_key})

        if path == "/delete_bot":
            body = self._read_json_body()
            if not body:
                return self._send_json({"error": "missing JSON body"}, status=400)
            bot_key = body.get("bot_key")
            admin_secret = body.get("admin_secret")
            if not bot_key:
                return self._send_json({"error": "bot_key required"}, status=400)
            required = os.environ.get(ADMIN_SECRET_ENV)
            if required:
                if admin_secret != required:
                    logger.warning("Unauthorized delete attempt from %s", self.client_address)
                    return self._send_json({"error": "invalid admin_secret"}, status=401)
            ok = delete_bot_token(bot_key)
            return self._send_json({"status": "deleted" if ok else "not_found", "bot_key": bot_key})

        if path == "/list_bots_admin":
            # admin-only listing with token masked
            body = self._read_json_body()  # optional admin auth in body
            required = os.environ.get(ADMIN_SECRET_ENV)
            provided = body.get("admin_secret") if body else None
            if required and provided != required:
                return self._send_json({"error": "invalid admin_secret"}, status=401)
            # mask tokens
            out = {k: ("set" if v else "none") for k, v in BOT_TOKENS.items()}
            return self._send_json({"bots": out})

        # webhook path for bots: /webhook/<bot_key>
        if path.startswith("/webhook/"):
            bot_key = unquote(path.split("/webhook/", 1)[1])
            token = get_bot_token(bot_key)
            # optional: verify secret token header if you used setWebhook with secret_token for that bot
            expected_secret = os.environ.get("WEBHOOK_SECRET")
            if expected_secret:
                header_secret = self.headers.get("X-Telegram-Bot-Api-Secret-Token")
                if header_secret != expected_secret:
                    logger.warning("Invalid webhook secret header for bot_key=%s", bot_key)
                    return self._send_json({"error": "invalid secret"}, status=401)

            if not token:
                logger.error("No token for bot_key=%s - cannot reply", bot_key)
                # still return 200 to acknowledge to Telegram (or 404 if you want Telegram to retry?),
                # but we log the problem. Return 200 to avoid retries.
                return self._send_json({"status": "no_token_for_bot_key"}, status=200)

            # read update
            try:
                length = int(self.headers.get("Content-Length", 0))
            except Exception:
                length = 0
            if length <= 0:
                logger.warning("Empty body for webhook bot_key=%s", bot_key)
                return self._send_json({"status": "no_body"}, status=200)
            raw = self.rfile.read(length)
            try:
                body_text = raw.decode("utf-8")
            except Exception:
                body_text = raw.decode("latin1", errors="replace")
            try:
                update = json.loads(body_text)
            except Exception:
                logger.error("Invalid JSON for bot_key=%s body=%s", bot_key, body_text[:200])
                return self._send_json({"status": "invalid_json"}, status=200)

            # compact log
            try:
                logger.info("Received update for %s: %s", bot_key, json.dumps(update, separators=(",", ":")))
            except Exception:
                logger.info("Received update for %s (non-serializable)", bot_key)

            # extract message
            chat_id = None
            text = ""
            if "message" in update and isinstance(update["message"], dict):
                msg = update["message"]
                chat_id = msg.get("chat", {}).get("id")
                text = msg.get("text") or ""
                logger.info("Message for %s from %s: %s", bot_key, chat_id, text)

            # ACK quickly
            self._send_json({"status": "ok"}, status=200)

            if not chat_id:
                return

            # build reply
            lower = (text or "").strip().lower()
            reply_text = None
            send_photo = False
            if lower.startswith("/start"):
                if IMAGE_URL.startswith(("http://","https://")):
                    reply_text = MESSAGE_TEXT
                    send_photo = True
                else:
                    reply_text = MESSAGE_TEXT + "\n\nNote: IMAGE_URL not public."
            elif lower.startswith("/help"):
                reply_text = "Commands: /start, /help"
            else:
                short = (text[:400] + "...") if len(text) > 400 else text
                reply_text = f"Received: {short}"

            # send via Telegram using the bot's token
            try:
                if send_photo and IMAGE_URL.startswith(("http://","https://")):
                    payload = {"chat_id": chat_id, "photo": IMAGE_URL, "caption": reply_text}
                    status, body = telegram_api_call(token, "sendPhoto", payload)
                else:
                    payload = {"chat_id": chat_id, "text": reply_text}
                    status, body = telegram_api_call(token, "sendMessage", payload)
                # log result already done in telegram_api_call
            except requests.exceptions.RequestException as e:
                logger.exception("Failed to send reply for bot_key=%s chat=%s error=%s", bot_key, chat_id, e)

            return

        # unknown POST
        self._send_json({"error": "unknown endpoint"}, status=404)

def run_server(port=8080):
    server_address = ("", port)
    httpd = HTTPServer(server_address, MultiBotHandler)
    def printer():
        logger.info("Server running. Register bots via POST /register_bot (admin-only).")
        logger.info("Set each bot's webhook to: https://<your-domain>/webhook/<bot_key>")
    threading.Thread(target=printer).start()
    try:
        logger.info("Starting Multi-bot Webhook server on port %s", port)
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping server")
    finally:
        httpd.server_close()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    # Optional: load tokens from TELEGRAM_TOKEN env var as single default (not used for multip bot pattern)
    env_token = os.environ.get("TELEGRAM_TOKEN")
    env_key = os.environ.get("TELEGRAM_KEY")  # optional single key
    if env_token and env_key:
        set_bot_token(env_key, env_token)
        logger.info("Loaded single TELEGRAM_TOKEN for key %s from environment", env_key)
    run_server(port)
