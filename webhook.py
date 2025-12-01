#!/usr/bin/env python3
"""
Simple Telegram webhook server that accepts bot token in the URL path:
  POST /bot/<BOT_TOKEN>

CAUTION: Exposing tokens in URLs is insecure. Use this only if you understand the risks.

Endpoints:
- POST /bot/<BOT_TOKEN>    -> Telegram webhook (uses token from URL to reply)
- GET  /bot/<BOT_TOKEN>    -> Quick info (no token printed)
- GET  /health             -> Health check (200)
- GET  /test               -> Test output

Run:
- Procfile: web: python webhook.py
- requirements.txt must include: requests
"""

import os
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote
import threading
import requests

# Configuration
REQUEST_TIMEOUT = 10
# If you want the bot to send a photo on /start, place a public HTTPS URL here:
PUBLIC_IMAGE_URL = ""  # Example: "https://example.com/static/token.jpg"
# Fallback text message (customize)
WELCOME_TEXT = "Welcome! Bot is online. Send /help to see commands."
HELP_TEXT = "Available commands:\n/start - Start\n/help - Help"

# Logging: do NOT include tokens in logs
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("bot-webhook")

def safe_log(msg, *args, **kwargs):
    """Use a single logger method to avoid accidentally logging tokens."""
    logger.info(msg, *args, **kwargs)

def telegram_api_post(token: str, method: str, payload: dict):
    """Call Telegram API with the given bot token and return (status_code, parsed_body_or_text)."""
    url = f"https://api.telegram.org/bot{token}/{method}"
    r = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    try:
        body = r.json()
    except Exception:
        body = r.text
    # Do not log the token. Log method, status and body summary.
    logger.info("Telegram API call %s -> status=%s body=%s", method, r.status_code, body)
    return r.status_code, body

class TokenInPathHandler(BaseHTTPRequestHandler):
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
        # path format: /bot/<BOT_TOKEN>
        path = urlparse(self.path).path
        if not path.startswith("/bot/"):
            return None
        token_part = path.split("/bot/", 1)[1]
        # URL-decode the token (so %3A -> :)
        token = unquote(token_part)
        return token if token else None

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            return self._send_json({"status": "healthy"}, status=200)
        if path == "/test":
            return self._send_json({"status": "ok", "note": "post updates to /bot/<TOKEN>"})
        if path.startswith("/bot/"):
            token = self._extract_token_from_path()
            if token:
                # Don't log the token. Instead log a masked form for debug (first 4 characters)
                masked = token[:4] + "..." if len(token) > 4 else "****"
                safe_log("Info: request for bot token (masked) %s", masked)
                return self._send_json({"status": "ok", "bot_token_masked": masked})
            return self._send_json({"error": "missing token in path"}, status=400)
        # Default
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        # Only handle /bot/<TOKEN> POSTs
        if not self.path.startswith("/bot/"):
            self.send_response(404)
            self.end_headers()
            return

        token = self._extract_token_from_path()
        if not token:
            self._send_json({"error": "missing token in path"}, status=400)
            return

        # Optional: check an incoming header secret if you want additional protection (not enabled by default)
        expected_secret = os.environ.get("WEBHOOK_SECRET")
        if expected_secret:
            header_secret = self.headers.get("X-Telegram-Bot-Api-Secret-Token")
            if header_secret != expected_secret:
                logger.warning("Invalid webhook secret header for token-in-path request (masked).")
                return self._send_json({"error": "invalid secret"}, status=401)

        body = self._read_json_body()
        if body is None:
            logger.warning("Empty or invalid JSON body for token-in-path webhook (masked).")
            return self._send_json({"status": "no body"}, status=200)

        # Compact log of incoming update (avoid multi-line)
        try:
            logger.info("Received update (masked token) - update_id=%s", body.get("update_id"))
        except Exception:
            logger.info("Received update (non-serializable)")

        # Extract message details
        chat_id = None
        text = ""
        try:
            if "message" in body and isinstance(body["message"], dict):
                msg = body["message"]
                chat_id = msg.get("chat", {}).get("id")
                text = msg.get("text") or ""
                logger.info("Message from chat_id=%s", chat_id)
        except Exception as e:
            logger.exception("Error extracting message: %s", e)

        # Acknowledge quickly to Telegram
        self._send_json({"status": "ok"}, status=200)

        # If no chat_id, nothing to do
        if not chat_id:
            return

        # Build reply based on message
        reply_text = None
        send_photo = False
        try:
            lower = (text or "").strip().lower()
            if lower.startswith("/start"):
                reply_text = WELCOME_TEXT
                if PUBLIC_IMAGE_URL and PUBLIC_IMAGE_URL.startswith(("http://","https://")):
                    send_photo = True
            elif lower.startswith("/help"):
                reply_text = HELP_TEXT
            else:
                short = (text[:400] + "...") if len(text) > 400 else text
                reply_text = f"Received: {short}"
        except Exception:
            reply_text = "Received your message."

        # Send the reply using the token extracted from the path
        try:
            if send_photo:
                payload = {"chat_id": chat_id, "photo": PUBLIC_IMAGE_URL, "caption": reply_text}
                status, body = telegram_api_post(token, "sendPhoto", payload)
            else:
                payload = {"chat_id": chat_id, "text": reply_text}
                status, body = telegram_api_post(token, "sendMessage", payload)
            # If Telegram returns not ok, you'll see that in logs (body)
        except requests.exceptions.RequestException as e:
            logger.exception("Failed to call Telegram API (masked token): %s", e)

def run_server(port=8080):
    server_address = ("", port)
    httpd = HTTPServer(server_address, TokenInPathHandler)

    def printer():
        logger.info("Server running. Use POST /bot/<BOT_TOKEN> as webhook target.")
        logger.info("Example (encode ':' as %3A if needed): https://<domain>/bot/<BOT_TOKEN>")
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
