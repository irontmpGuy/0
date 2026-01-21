# proxy.py
import socketserver
from sockshandler import SOCKS5Server

HOST, PORT = "0.0.0.0", 2180
server = SOCKS5Server((HOST, PORT))
print(f"SOCKS5 proxy running on {HOST}:{PORT}")
server.serve_forever()

