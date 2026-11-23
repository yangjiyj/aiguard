#!/usr/bin/env python3
"""Mock OpenAI-compatible HTTP server for proxy testing."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json


class MockHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        try:
            req = json.loads(body)
            model = req.get('model', 'unknown')
        except json.JSONDecodeError:
            model = 'unknown'

        resp = {
            'id': 'chatcmpl-mock',
            'object': 'chat.completion',
            'created': 1234567890,
            'model': model,
            'choices': [{
                'index': 0,
                'message': {
                    'role': 'assistant',
                    'content': 'This is a mock response for proxy testing.'
                },
                'finish_reason': 'stop'
            }],
            'usage': {
                'prompt_tokens': 10,
                'completion_tokens': 10,
                'total_tokens': 20
            }
        }
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, format, *args):
        print(f"[MOCK] {args[0]} {args[1]} {args[2]}")


if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8000), MockHandler)
    print('Mock provider listening on port 8000...')
    server.serve_forever()
