from http.server import BaseHTTPRequestHandler, HTTPServer
import html
import json


class App(BaseHTTPRequestHandler):
    def do_GET(self):
        claims = {name: self.headers.get('X-Forwarded-' + name, '')
                  for name in ('User', 'Subject', 'Provider', 'Email')}
        if self.path == '/claims':
            body = json.dumps(claims, indent=2).encode()
            content_type = 'application/json'
        else:
            body = ('<!doctype html><html lang="en"><meta charset="utf-8">'
                    '<title>ML-DSA Federation test app</title>'
                    '<style>body{font:18px system-ui;max-width:850px;margin:4rem auto;padding:1rem}'
                    'pre{background:#eee;padding:1rem;white-space:pre-wrap}</style>'
                    '<h1>You are logged in through OFFA</h1>'
                    '<p>These identity headers came from OFFA after authentication with SSP.</p>'
                    '<pre>' + html.escape(json.dumps(claims, indent=2)) + '</pre>'
                    '<p><a href="/claims">View identity as JSON</a></p></html>').encode()
            content_type = 'text/html; charset=utf-8'
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)


HTTPServer(('0.0.0.0', 8000), App).serve_forever()
