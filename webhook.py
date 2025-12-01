#!/usr/bin/env python3
"""
Token-in-path Telegram webhook server.

Endpoints:
- POST /bot/<BOT_TOKEN>    -> Telegram webhook (uses token from URL to reply)
- GET  /bot/<BOT_TOKEN>    -> Info (masked)
- GET  /health             -> Health check (200)
- GET  /test               -> Test output

CAUTION: Embedding tokens in URLs is insecure (browser history, logs, proxies).
Use only if you accept that risk.
"""

import os
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote
import threading
import requests

# -----------------------------
# CONFIGURE: replace here only
# -----------------------------
# Public image URL (will be sent by the bot as photo on /start)
PUBLIC_IMAGE_URL = "static/token.jpg"

# Message to send as caption (or text if photo sending fails)
MESSAGE_TEXT = """𝗠𝗲𝗴𝗮 / 𝗗𝗶𝗿𝗲𝗰𝘁 𝗟𝗶𝗻𝗸 / 𝗦𝘁𝗿𝗲𝗮𝗺 𝗙𝘂𝗹𝗹 𝗛𝗗 𝗣𝗢*𝗡

👇🏻👇🏻👇🏻👇🏻👇🏻👇🏻👇🏻👇🏻
https://t.me/+Lxow3aJc3z1lMDA1
https://t.me/+Lxow3aJc3z1lMDA1
https://t.me/+Lxow3aJc3z1lMDA1
https://t.me/+Lxow3aJc3z1lMDA1
https://t.me/+Lxow3aJc3z1lMDA1

👆🏻👆🏻👆🏻👆🏻👆🏻👆🏻👆🏻👆🏻
"""

# Reply texts
WELCOME_TEXT = "Welcome! Bot is online. Send /help to see commands."
HELP_TEXT = "Available commands:\n/start - Start the bot\n/help - This help text"

# Timeout for outgoing requests to Telegram
REQUEST_TIMEOUT = 10

# -----------------------------
# Do not change below unless you know what you're doing
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("token-path-webhook")

def _safe_log(msg, *args, **kwargs):
    """Simple wrapper so we centralize logging usage (avoid printing tokens)."""
    logger.info(msg, *args, **kwargs)

def telegram_api_post(token: str, method: str, payload: dict):
    """Call Telegram HTTP API and return (status_code, parsed_body_or_text)."""
    url = f"https://api.telegram.org/bot{token}/{method}"
    r = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    try:
        body = r.json()
    except Exception:
        body = r.text
    # Log method and response; never include token in logs.
    logger.info("Telegram API %s -> status=%s body=%s", method, r.status_code, body)
    return r.status_code, body

class TokenPathHandler(BaseHTTPRequestHandler):
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

    def _extract_token_from_path(self):
        # expected path: /bot/<TOKEN>
        path = urlparse(self.path).path
        if not path.startswith("/bot/"):
            return None
        token_part = path.split("/bot/", 1)[1]
        token = unquote(token_part)
        return token if token else None

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            return self._send_json({"status": "healthy"}, status=200)
        if path == "/test":
            return self._send_json({"status": "ok", "note": "POST updates to /bot/<TOKEN>"}, status=200)
        if path.startswith("/bot/"):
            token = self._extract_token_from_path()
            if token:
                masked = token[:4] + "..." if len(token) > 4 else "****"
                _safe_log("Info: GET /bot request for masked token %s", masked)
                return self._send_json({"status": "ok", "bot_token_masked": masked})
            return self._send_json({"error": "missing token in path"}, status=400)
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        # only accept /bot/<TOKEN>
        if not self.path.startswith("/bot/"):
            self.send_response(404)
            self.end_headers()
            return

        token = self._extract_token_from_path()
        if not token:
            return self._send_json({"error": "missing token in path"}, status=400)

        # Optional: verify secret header if you want additional protection
        expected_secret = os.environ.get("WEBHOOK_SECRET")
        if expected_secret:
            header_secret = self.headers.get("X-Telegram-Bot-Api-Secret-Token")
            if header_secret != expected_secret:
                logger.warning("Invalid webhook secret header (masked token request).")
                return self._send_json({"error": "invalid secret"}, status=401)

        body = self._read_json_body()
        if body is None:
            logger.warning("Empty or invalid JSON body for token-in-path webhook.")
            return self._send_json({"status": "no body"}, status=200)

        # Log arrival (avoid multi-line dumps)
        try:
            _safe_log("Received update id=%s", body.get("update_id"))
        except Exception:
            _safe_log("Received update (non-serializable)")

        # Extract chat & text
        chat_id = None
        text = ""
        try:
            if "message" in body and isinstance(body["message"], dict):
                msg = body["message"]
                chat_id = msg.get("chat", {}).get("id")
                text = msg.get("text") or ""
                _safe_log("Message from chat_id=%s", chat_id)
        except Exception as e:
            logger.exception("Error extracting message: %s", e)

        # Acknowledge to Telegram quickly
        self._send_json({"status": "ok"}, status=200)

        if not chat_id:
            return

        # Build reply
        reply_text = None
        send_photo = False
        try:
            lower = (text or "").strip().lower()
            if lower.startswith("/start"):
                reply_text = MESSAGE_TEXT if MESSAGE_TEXT else WELCOME_TEXT
                if PUBLIC_IMAGE_URL and PUBLIC_IMAGE_URL.startswith(("http://", "https://")):
                    send_photo = True
            elif lower.startswith("/help"):
                reply_text = HELP_TEXT
            else:
                short = (text[:400] + "...") if len(text) > 400 else text
                reply_text = f"Received: {short}"
        except Exception:
            reply_text = "Received your message."

        # Send reply (using token from path). We do a best-effort send.
        try:
            if send_photo:
                payload = {"chat_id": chat_id, "photo": PUBLIC_IMAGE_URL, "caption": reply_text}
                telegram_api_post(token, "sendPhoto", payload)
            else:
                payload = {"chat_id": chat_id, "text": reply_text}
                telegram_api_post(token, "sendMessage", payload)
        except requests.exceptions.RequestException as e:
            logger.exception("Failed to call Telegram API (masked token): %s", e)

def run_server(port=8080):
    server_address = ("", port)
    httpd = HTTPServer(server_address, TokenPathHandler)

    def printer():
        logger.info("Server running. Use POST /bot/<BOT_TOKEN> as webhook target.")
        logger.info("Example: https://webhook-production-b366.up.railway.app/bot/<BOT_TOKEN>")
        logger.info("Health: /health  Test: /test")
    threading.Thread(target=printer).start()

    try:
        logger.info("Starting server on port %s", port)
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        httpd.server_close()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    run_server(port)

