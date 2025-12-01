#!/usr/bin/env python3
"""
Telegram webhook server that accepts a bot token at runtime and replies to messages.

Endpoints:
- GET  /                 -> Info page
- POST /set_token        -> Set bot token (JSON: {"token": "...", "admin_secret": "..."})
- GET  /token_status     -> Returns whether token is set (no token value)
- POST /webhook          -> Telegram webhook (replies to /start, /help, echoes)
- GET  /health           -> Health check
- GET  /test             -> Test response

SECURITY:
- If ADMIN_SECRET env var is set, /set_token requires that secret.
- Token is saved to ./.bot_token (file permission 600) so it survives restarts.
- Avoid exposing ADMIN_SECRET. If ADMIN_SECRET is not set, server will accept one-time token (less secure).
"""

import os
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import threading
import requests
import stat

# Config
TOKEN_FILE = ".bot_token"   # local file to persist token (0600)
REQUEST_TIMEOUT = 10        # seconds for Telegram API calls
IMAGE_URL = "https://ik.imagekit.io/mhbes43vr/token.jpg"  # change to public https url if you want sendPhoto
ADMIN_SECRET_ENV = "ADMIN_SECRET"  # optional env var to require auth to set token

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("webhook")

# Helpers for token storage
def save_token_to_file(token: str):
    """Save token to disk with restrictive permissions."""
    with open(TOKEN_FILE, "w") as f:
        f.write(token.strip())
    # set file mode to 600
    try:
        os.chmod(TOKEN_FILE, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as e:
        logger.warning("Could not chmod token file: %s", e)

def load_token_from_file():
    """Load token from disk if present."""
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r") as f:
                t = f.read().strip()
                return t if t else None
        except Exception as e:
            logger.error("Error reading token file: %s", e)
            return None
    # fallback to env var
    return os.environ.get("TELEGRAM_TOKEN")

def clear_token_file():
    try:
        if os.path.exists(TOKEN_FILE):
            os.remove(TOKEN_FILE)
    except Exception as e:
        logger.warning("Could not remove token file: %s", e)

# In-memory token (loaded at startup)
BOT_TOKEN = load_token_from_file()

def is_token_set():
    return bool(BOT_TOKEN)

def set_bot_token(new_token: str, persist=True):
    global BOT_TOKEN
    BOT_TOKEN = new_token.strip()
    if persist:
        save_token_to_file(BOT_TOKEN)

# helper to call telegram API and log responses
def telegram_api_call(path: str, payload: dict):
    token = BOT_TOKEN
    if not token:
        raise RuntimeError("TELEGRAM_TOKEN not set")
    url = f"https://api.telegram.org/bot{token}/{path}"
    r = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    try:
        body = r.json()
    except Exception:
        body = r.text
    logger.info("Telegram API %s response status=%s body=%s", path, r.status_code, body)
    return r.status_code, body

class TelegramWebhookHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except Exception:
            length = 0
        if length == 0:
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
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            token_status = "set" if is_token_set() else "not set"
            admin_required = bool(os.environ.get(ADMIN_SECRET_ENV))
            self.wfile.write(f"""
                <html><body style="font-family:Arial,sans-serif;padding:20px;">
                <h2>Telegram Webhook Server</h2>
                <p>Token status: <b>{token_status}</b></p>
                <p>Set token: POST JSON to <code>/set_token</code> with fields <code>token</code> and (if required) <code>admin_secret</code>.</p>
                <p>Admin secret required: <b>{admin_required}</b></p>
                <p>Webhook endpoint: <code>/webhook</code></p>
                <p>Test endpoint: <a href="/test">/test</a></p>
                </body></html>
            """.encode())
        elif parsed.path == "/health":
            self._send_json({"status": "healthy"})
        elif parsed.path == "/test":
            self._send_json({
                "status": "ok",
                "token_set": is_token_set(),
                "note": "POST /webhook with Telegram-style JSON to test"
            })
        elif parsed.path == "/token_status":
            self._send_json({"token_set": is_token_set()})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/set_token":
            body = self._read_json_body()
            if not body or "token" not in body:
                return self._send_json({"error": "missing token in JSON body"}, status=400)
            provided_token = body.get("token", "").strip()
            admin_required = os.environ.get(ADMIN_SECRET_ENV)
            if admin_required:
                provided_secret = body.get("admin_secret", "")
                if provided_secret != admin_required:
                    logger.warning("Invalid admin secret attempt from %s", self.client_address)
                    return self._send_json({"error": "invalid admin_secret"}, status=401)
            # set token (persist to file)
            try:
                set_bot_token(provided_token, persist=True)
                logger.info("Bot token set (persisted to %s)", TOKEN_FILE)
                return self._send_json({"status": "token set"})
            except Exception as e:
                logger.exception("Failed to save token: %s", e)
                return self._send_json({"error": "failed to save token"}, status=500)

        if parsed.path == "/webhook":
            # Optional: verify secret token header if you used setWebhook with secret_token
            expected_secret = os.environ.get("WEBHOOK_SECRET")
            if expected_secret:
                header_secret = self.headers.get("X-Telegram-Bot-Api-Secret-Token")
                if header_secret != expected_secret:
                    logger.warning("Invalid or missing webhook secret header")
                    return self._send_json({"error": "invalid secret"}, status=401)

            # read update
            raw_body = self._read_json_body()
            if raw_body is None:
                logger.warning("Empty or invalid JSON body on /webhook")
                return self._send_json({"status": "no body"}, status=200)

            # compact log
            try:
                logger.info("Received update: %s", json.dumps(raw_body, separators=(",", ":")))
            except Exception:
                logger.info("Received update (non-serializable)")

            # extract chat and text
            chat_id = None
            text = ""
            try:
                if "message" in raw_body and isinstance(raw_body["message"], dict):
                    msg = raw_body["message"]
                    chat_id = msg.get("chat", {}).get("id")
                    text = msg.get("text") or ""
                    logger.info("Message from %s: %s", chat_id, text)
            except Exception as e:
                logger.exception("Error extracting message: %s", e)

            # respond 200 quickly so Telegram won't retry
            self._send_json({"status": "ok"}, status=200)

            # if no chat_id, nothing to reply
            if not chat_id:
                return

            # if token not set, log and return
            if not is_token_set():
                logger.error("No bot token set; cannot send reply to chat %s", chat_id)
                return

            # Build a reply
            reply_text = None
            send_photo = False
            try:
                lower = (text or "").strip().lower()
                if lower.startswith("/start"):
                    # If IMAGE_URL is a public https/http URL, send as photo with caption
                    if IMAGE_URL.startswith("http://") or IMAGE_URL.startswith("https://"):
                        reply_text = MESSAGE_TEXT if 'MESSAGE_TEXT' in globals() else "Welcome!"
                        send_photo = True
                    else:
                        reply_text = MESSAGE_TEXT if 'MESSAGE_TEXT' in globals() else "Welcome! (image not public)"
                elif lower.startswith("/help"):
                    reply_text = "Available commands:\n/start - Start\n/help - Help"
                else:
                    # default: short echo (prevent very long echoes)
                    short = (text[:400] + "...") if len(text) > 400 else text
                    reply_text = f"Received: {short}"
            except Exception:
                reply_text = "Received your message."

            # Send via Telegram API
            try:
                if send_photo and IMAGE_URL.startswith(("http://", "https://")):
                    payload = {"chat_id": chat_id, "photo": IMAGE_URL, "caption": reply_text}
                    status, body = telegram_api_call("sendPhoto", payload)
                else:
                    payload = {"chat_id": chat_id, "text": reply_text}
                    status, body = telegram_api_call("sendMessage", payload)
            except Exception as e:
                logger.exception("Failed to send Telegram reply: %s", e)

            return

        # unknown POST endpoint
        self.send_response(404)
        self.end_headers()


def run_server(port=8080):
    server_address = ("", port)
    httpd = HTTPServer(server_address, TelegramWebhookHandler)
    # print instructions on background thread
    def printer():
        host_url = f"http://localhost:{port}" if port in (8080, 5000) else f"http://YOUR_SERVER:{port}"
        logger.info("Server running. Set webhook URL as: https://<your-domain>/webhook")
        logger.info("To set token: POST JSON to /set_token with {token:'...', admin_secret:'...'}")
    threading.Thread(target=printer).start()
    try:
        logger.info("Starting server on port %s", port)
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping server")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    # load token from file or env at startup (already done via BOT_TOKEN global)
    # if env TELEGRAM_TOKEN provided, it overrides file at startup
    env_token = os.environ.get("TELEGRAM_TOKEN")
    if env_token:
        set_bot_token(env_token, persist=True)
        logger.info("Loaded TELEGRAM_TOKEN from environment and persisted to file.")
    run_server(port)
