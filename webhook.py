#!/usr/bin/env python3
"""
Simple Telegram Webhook Server (production-ready updates)
- Replies to /start and /help
- Echoes other messages
- Optional secret-token verification (WEBHOOK_SECRET)
- Defensive JSON parsing and logging
- Logs Telegram API response for outgoing messages

Deploy: set TELEGRAM_TOKEN in environment (Railway Variables)
Set webhook: https://api.telegram.org/bot<YOUR_TOKEN>/setWebhook?url=https://<your-domain>/webhook
(or include &secret_token=MYSECRET and set WEBHOOK_SECRET=MYSECRET in Railway)
"""

import os
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Your message (customize this)
MESSAGE_TEXT = """𝗠𝗲𝗴𝗮 / 𝗗𝗶𝗿𝗲𝗰𝘁 𝗟𝗶𝗻𝗸 / 𝗦𝘁𝗿𝗲𝗮𝗺 𝗙𝘂𝗹𝗹 𝗛𝗗 𝗣𝗢*𝗡

👇🏻👇🏻👇🏻👇🏻👇🏻👇🏻👇🏻👇🏻
https://t.me/+Lxow3aJc3z1lMDA1
https://t.me/+Lxow3aJc3z1lMDA1
https://t.me/+Lxow3aJc3z1lMDA1
https://t.me/+Lxow3aJc3z1lMDA1
https://t.me/+Lxow3aJc3z1lMDA1

👆🏻👆🏻👆🏻👆🏻👆🏻👆🏻👆🏻👆🏻"""

# Your image URL (CHANGE THIS to a public https URL if you want Telegram to fetch it)
# Example: IMAGE_URL = "https://example.com/static/token.jpg"
IMAGE_URL = "static/token.jpg"

# Timeout for requests to Telegram
REQUEST_TIMEOUT = 10


class TelegramWebhookHandler(BaseHTTPRequestHandler):
    """HTTP handler for Telegram webhooks"""

    def _send_json(self, data, status=200):
        """Helper to send JSON responses"""
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)

        if parsed_path.path == '/':
            # Home page - shows instructions
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            instructions = """
            <html>
            <head><title>Telegram Bot Webhook</title></head>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h1>✅ Telegram Bot Webhook is Running!</h1>
                <p>Your webhook server is online.</p>

                <h2>📝 How to Set Up Your Bot:</h2>
                <ol>
                    <li>Get your bot token from @BotFather</li>
                    <li>Set webhook using this command:</li>
                    <code style="background: #f0f0f0; padding: 10px; display: block; margin: 10px 0;">
                        https://api.telegram.org/botYOUR_BOT_TOKEN/setWebhook?url=https://YOUR-URL-HERE/webhook
                    </code>
                    <li>OPTIONAL: add &amp;secret_token=MY_SECRET and set WEBHOOK_SECRET=MY_SECRET in the server</li>
                    <li>Send any message to your bot to test</li>
                </ol>

                <h2>🔗 Endpoints:</h2>
                <ul>
                    <li><code>GET /</code> - This page</li>
                    <li><code>POST /webhook</code> - Telegram webhook endpoint</li>
                    <li><code>GET /health</code> - Health check</li>
                    <li><code>GET /test</code> - Test webhook response</li>
                </ul>

                <p><strong>Note:</strong> This server only receives webhooks. Bot token is NOT stored here in the code — use environment variables.</p>
            </body>
            </html>
            """
            self.wfile.write(instructions.encode())

        elif parsed_path.path == '/health':
            # Health check endpoint
            response = {'status': 'healthy', 'service': 'telegram-webhook'}
            self._send_json(response, status=200)

        elif parsed_path.path == '/test':
            # Test endpoint - shows what webhook will respond with
            test_response = {
                'message': 'Webhook is working!',
                'your_message': MESSAGE_TEXT,
                'image_url': IMAGE_URL,
                'note': 'This is what your bot will send to users (if IMAGE_URL is a public https URL)'
            }
            self._send_json(test_response, status=200)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        """Handle POST requests (Telegram webhook)"""
        if self.path != '/webhook':
            self.send_response(404)
            self.end_headers()
            return

        # Optional secret-token verification (if you set a secret when calling setWebhook)
        expected_secret = os.environ.get('WEBHOOK_SECRET')
        if expected_secret:
            header_secret = self.headers.get('X-Telegram-Bot-Api-Secret-Token')
            if header_secret != expected_secret:
                logger.warning("Invalid or missing secret token header: %s", header_secret)
                # Return 401 to indicate unauthorized (Telegram will not retry if unauthorized)
                self._send_json({"error": "invalid secret token"}, status=401)
                return

        # Read body safely
        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except Exception:
            content_length = 0

        if content_length <= 0:
            logger.warning("Empty POST body received from %s", self.client_address)
            # Acknowledge so Telegram won't keep retrying
            self._send_json({"status": "empty body"}, status=200)
            return

        raw = self.rfile.read(content_length)
        try:
            body_text = raw.decode('utf-8')
        except Exception:
            body_text = raw.decode('latin1', errors='replace')

        try:
            update = json.loads(body_text)
        except json.JSONDecodeError:
            logger.error("Invalid JSON received: %s", body_text)
            self._send_json({"error": "invalid json"}, status=200)
            return

        # Log the update as a compact single-line JSON to avoid interleaving logs
        try:
            logger.info("Received update: %s", json.dumps(update, separators=(',', ':')))
        except Exception:
            logger.info("Received update (non-serializable)")

        # Process message if present
        chat_id = None
        text = None
        try:
            if 'message' in update and isinstance(update['message'], dict):
                message = update['message']
                chat_id = message.get('chat', {}).get('id')
                text = message.get('text', '') or ''
                logger.info("Message from %s: %s", chat_id, text)
        except Exception as e:
            logger.exception("Error extracting message: %s", e)

        # Send acknowledgement response quickly to Telegram
        # (we'll also attempt to send a reply via Telegram API)
        ack = {
            'status': 'ok',
            'message': 'Webhook received successfully'
        }
        self._send_json(ack, status=200)

        # If there's no chat_id or no text, nothing to reply with
        if not chat_id:
            return

        # Build reply text
        reply_text = None
        try:
            lower = text.strip().lower()
            if lower.startswith('/start'):
                # If IMAGE_URL is a public http(s) URL, send a photo with caption; otherwise send message
                if IMAGE_URL.startswith('http://') or IMAGE_URL.startswith('https://'):
                    reply_text = MESSAGE_TEXT
                    send_photo = True
                else:
                    # IMAGE_URL not public — send text only (include image path note)
                    reply_text = MESSAGE_TEXT + "\n\nNote: IMAGE_URL is not a public URL. Use a full https URL to send a photo."
                    send_photo = False
            elif lower.startswith('/help'):
                reply_text = "Available commands:\n/start - Start the bot\n/help - Show help"
                send_photo = False
            else:
                # default: echo back a short acknowledgement (avoid echoing very long content)
                short = (text[:400] + '...') if len(text) > 400 else text
                reply_text = f"Received your message: {short}"
                send_photo = False
        except Exception:
            reply_text = "Received your message."
            send_photo = False

        # Send reply using Telegram API
        token = os.environ.get('TELEGRAM_TOKEN')
        if not token:
            logger.error("TELEGRAM_TOKEN not set; cannot send reply to chat %s", chat_id)
            return

        # Helper to log Telegram responses
        def log_resp(r):
            try:
                data = r.json()
            except Exception:
                data = r.text
            logger.info("Telegram API response (status=%s) => %s", r.status_code, data)

        try:
            if send_photo and IMAGE_URL.startswith(('http://', 'https://')):
                payload = {"chat_id": chat_id, "photo": IMAGE_URL, "caption": reply_text}
                r = requests.post(f"https://api.telegram.org/bot{token}/sendPhoto", json=payload, timeout=REQUEST_TIMEOUT)
                log_resp(r)
            else:
                payload = {"chat_id": chat_id, "text": reply_text}
                r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", json=payload, timeout=REQUEST_TIMEOUT)
                log_resp(r)
        except requests.exceptions.RequestException as e:
            logger.exception("Failed to send message to Telegram: %s", e)

    def log_message(self, format, *args):
        """Override to use our logger instead of printing to stderr"""
        # Use remote address rather than DNS reverse lookup (faster)
        remote = self.client_address[0]
        logger.info("%s - %s" % (remote, format % args))


def get_server_url(port):
    """Get server URL for instructions"""
    # For local testing
    if port in (8080, 5000):
        return f"http://localhost:{port}"
    # For production, you'll need to use your actual URL (Railway supplies https)
    return f"http://YOUR_SERVER_IP:{port}"


def print_instructions(port):
    """Print deployment instructions"""
    url = get_server_url(port)

    print("\n" + "=" * 60)
    print("🚀 TELEGRAM BOT WEBHOOK SERVER")
    print("=" * 60)
    print(f"\n✅ Server is running on: {url}")
    print("\n📝 TO SET UP YOUR BOT:")
    print("1. Get your bot token from @BotFather")
    print("2. Replace YOUR_BOT_TOKEN in this command:")
    print(f"\n   Command to set webhook:")
    print(f"   curl -X GET 'https://api.telegram.org/botYOUR_BOT_TOKEN/setWebhook?url={url}/webhook'")
    print(f"\n   Or visit in browser:")
    print(f"   https://api.telegram.org/botYOUR_BOT_TOKEN/setWebhook?url={url}/webhook")
    print("\n   If you want additional security, add &secret_token=MY_SECRET to the URL and set WEBHOOK_SECRET=MY_SECRET")
    print("\n3. Test your bot by sending any message")
    print("\n🔗 Quick links:")
    print(f"   Home: {url}/")
    print(f"   Health: {url}/health")
    print(f"   Test: {url}/test")
    print("\n📌 IMPORTANT: Update IMAGE_URL in the code with a public https URL if you want Telegram to fetch the image.")
    print("=" * 60 + "\n")


def run_server(port=8080):
    """Run the HTTP server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, TelegramWebhookHandler)

    # Print instructions in a separate thread so it doesn't block
    threading.Thread(target=print_instructions, args=(port,)).start()

    logger.info(f"Starting server on port {port}...")
    print(f"Press Ctrl+C to stop the server")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
    finally:
        httpd.server_close()


if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 8080))

    # Run the server
    run_server(port)
