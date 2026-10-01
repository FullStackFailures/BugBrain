from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        item = params.get("id", ["1"])[0]

        if parsed.path == "/":
            body = f"""
            <html>
            <head><title>BugBrain Active Test</title></head>
            <body>
                <h1>BugBrain Active Verification Test</h1>
                <p>Test item: {item}</p>
                <a href="/item?id=1">Item 1</a>
                <a href="/item?id=2">Item 2</a>
            </body>
            </html>
            """

        elif parsed.path == "/item":
            body = f"""
            <html>
            <head><title>Item</title></head>
            <body>
                <h1>Item {item}</h1>
                <p>Controlled local test response.</p>
            </body>
            </html>
            """

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>404</h1>")
            return

        data = body.encode()

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        print("[TEST-SERVER]", format % args)


server = HTTPServer(("127.0.0.1", 8000), Handler)

print("BugBrain active-verification test server")
print("Listening on http://127.0.0.1:8000")
print("Press Ctrl+C to stop.")

server.serve_forever()
