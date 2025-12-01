#!/usr/bin/env python3
"""
Simple Telegram Webhook Server
Deploy this, get the URL, then set webhook from your computer
Command: https://api.telegram.org/botYOUR_TOKEN/setWebhook?url=YOUR_URL/webhook
"""

import os
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

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

# Your image URL (CHANGE THIS!)
IMAGE_URL = "static/token.jpg"  # ⬅️ REPLACE WITH YOUR IMAGE URL

class TelegramWebhookHandler(BaseHTTPRequestHandler):
    """HTTP handler for Telegram webhooks"""
    
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
                    <li>Send any message to your bot to test</li>
                </ol>
                
                <h2>🔗 Endpoints:</h2>
                <ul>
                    <li><code>GET /</code> - This page</li>
                    <li><code>POST /webhook</code> - Telegram webhook endpoint</li>
                    <li><code>GET /health</code> - Health check</li>
                    <li><code>GET /test</code> - Test webhook response</li>
                </ul>
                
                <p><strong>Note:</strong> This server only receives webhooks. Bot token is NOT stored here.</p>
                <p>You must set the webhook URL from YOUR computer using YOUR bot token.</p>
            </body>
            </html>
            """
            self.wfile.write(instructions.encode())
            
        elif parsed_path.path == '/health':
            # Health check endpoint
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {'status': 'healthy', 'service': 'telegram-webhook'}
            self.wfile.write(json.dumps(response).encode())
            
        elif parsed_path.path == '/test':
            # Test endpoint - shows what webhook will respond with
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            test_response = {
                'message': 'Webhook is working!',
                'your_message': MESSAGE_TEXT,
                'image_url': IMAGE_URL,
                'note': 'This is what your bot will send to users'
            }
            self.wfile.write(json.dumps(test_response, indent=2).encode())
            
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """Handle POST requests (Telegram webhook)"""
        if self.path == '/webhook':
            try:
                # Read the request body
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                
                # Parse JSON data from Telegram
                update = json.loads(post_data.decode('utf-8'))
                
                # Log the update
                logger.info(f"Received update: {json.dumps(update, indent=2)}")
                
                # Extract chat ID if it's a message
                chat_id = None
                if 'message' in update:
                    message = update['message']
                    chat_id = message.get('chat', {}).get('id')
                    text = message.get('text', '')
                    logger.info(f"Message from {chat_id}: {text}")
                
                # Send response back to Telegram (acknowledgement)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                
                # Telegram expects this response structure
                response = {
                    'status': 'ok',
                    'message': 'Webhook received successfully',
                    'note': 'Bot responses are handled by Telegram API',
                    'your_bot_should_send': {
                        'photo_url': IMAGE_URL,
                        'caption': MESSAGE_TEXT
                    }
                }
                self.wfile.write(json.dumps(response).encode())
                
            except Exception as e:
                logger.error(f"Error processing webhook: {str(e)}")
                self.send_response(500)
                self.end_headers()
                error_response = {'error': str(e)}
                self.wfile.write(json.dumps(error_response).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        """Override to use our logger instead of printing to stderr"""
        logger.info("%s - %s" % (self.address_string(), format % args))

def get_server_url(port):
    """Get server URL for instructions"""
    # For local testing
    if port == 8080:
        return f"http://localhost:{port}"
    # For production, you'll need to use your actual URL
    return f"http://YOUR_SERVER_IP:{port}"

def print_instructions(port):
    """Print deployment instructions"""
    url = get_server_url(port)
    
    print("\n" + "="*60)
    print("🚀 TELEGRAM BOT WEBHOOK SERVER")
    print("="*60)
    print(f"\n✅ Server is running on: {url}")
    print("\n📝 TO SET UP YOUR BOT:")
    print("1. Get your bot token from @BotFather")
    print("2. Replace YOUR_BOT_TOKEN in this command:")
    print(f"\n   Command to set webhook:")
    print(f"   curl -X GET 'https://api.telegram.org/botYOUR_BOT_TOKEN/setWebhook?url={url}/webhook'")
    print(f"\n   Or visit in browser:")
    print(f"   https://api.telegram.org/botYOUR_BOT_TOKEN/setWebhook?url={url}/webhook")
    print("\n3. Test your bot by sending any message")
    print("\n🔗 Quick links:")
    print(f"   Home: {url}/")
    print(f"   Health: {url}/health")
    print(f"   Test: {url}/test")
    print("\n📌 IMPORTANT: Update IMAGE_URL in the code with your actual image!")
    print("="*60 + "\n")

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

