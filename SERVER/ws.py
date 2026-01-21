import socket
import threading
import base64
import hashlib
import struct
import queue
import time
import sys

HOST = '0.0.0.0'
PORT = 8576
GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

# Each client has a queue of actions to send
client_queues = {}

LOG_FILE = "./ws.log"

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line)

def clear_log():
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] --LOG-FILE-START--\n"
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write(line)

def send_ws(conn, data: bytes, binary: bool = False):
    frame = bytearray()
    opcode = 0x2 if binary else 0x1
    frame.append(0x80 | opcode)  # FIN + opcode

    length = len(data)
    if length <= 125:
        frame.append(length)
    elif length <= 0xFFFF:
        frame.append(126)
        frame.extend(struct.pack(">H", length))
    else:
        frame.append(127)
        frame.extend(struct.pack(">Q", length))

    frame.extend(data)

    # debug: print frame hex and ascii
    try:
        hexs = " ".join(f"{b:02X}" for b in frame[:64]) + (" ..." if len(frame)>64 else "")
        try:
            ascii = frame.decode('utf-8', errors='replace')
        except:
            ascii = "<non-utf8>"
        log(f"[send_ws] sending {len(frame)} bytes: {hexs}  ascii={ascii!r}")
    except Exception as e:
        log(f"send_ws debug failed: {e}")

    conn.sendall(frame)

def websocket_handshake(conn, addr):
    """Perform handshake and return True if success."""
    data = conn.recv(4096).decode('utf-8', errors='ignore')
    headers = {}
    for line in data.split("\r\n")[1:]:
        if ": " in line:
            k,v = line.split(": ",1)
            headers[k.lower()] = v

    key = headers.get("sec-websocket-key","")
    accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    resp = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
    )
    conn.send(resp.encode('utf-8'))
    return True

import select
import sys
import struct

def recv_one_frame(conn, timeout=None):
    """
    Receive one WebSocket frame from the client.
    Returns (opcode, payload) or (None, None) if closed or interrupted.
    """
    try:
        while True:
            rlist, _, _ = select.select([conn], [], [], timeout)
            if not rlist:
                return None, None
            
            if conn in rlist:
                header = conn.recv(2)
                if len(header) < 2:
                    return None, None
                b1, b2 = header
                opcode = b1 & 0x0F
                masked = b2 & 0x80
                payload_len = b2 & 0x7F

                if payload_len == 126:
                    ext = conn.recv(2)
                    payload_len = struct.unpack(">H", ext)[0]
                elif payload_len == 127:
                    ext = conn.recv(8)
                    payload_len = struct.unpack(">Q", ext)[0]

                if masked:
                    masking_key = conn.recv(4)

                payload = b''
                while len(payload) < payload_len:
                    chunk = conn.recv(payload_len - len(payload))
                    if not chunk:
                        return None, None
                    payload += chunk

                if masked:
                    payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

                if opcode == 0x9:
                    pong = struct.pack("BB", 0x8A, len(payload)) + payload
                    conn.send(pong)
                    continue

                if opcode == 0x8:
                    return None, None

                return opcode, payload

    except Exception as e:
        log(f"[ERROR] recv_one_frame exception: {e}")
        return None, None
    

def recieve(conn, timeout=None):
    opcode, payload = recv_one_frame(conn, timeout=timeout)
    if opcode == 0x1:
        response = payload.decode(errors='ignore')
        return response
    elif opcode == 0x2:
        fn = f"result_{int(time.time())}.bin"
        with open(fn, "wb") as f:
            f.write(payload)
        log(f"Result from client (binary) saved: {fn}")
    return None

RECIEVE_COUNTER = 0

def admin(conn, client_conn, timeout=None):
    global clientConn, adminConn, RECIEVE_COUNTER
    if is_socket_dead(conn):
            log("admin socket dead.")
            conn_reset(client_conn, conn)
            return False
    resp = recieve(conn, timeout=timeout)
    if resp is not None:
        RECIEVE_COUNTER = 0
        log(f"Command from Admin: {resp}")
        if "__quit_ws__" in resp.strip().lower():
            sys.exit(0)
    
        log("Waiting for client Reply...")
        if client_conn:
            clientResp = client(client_conn, resp)
            if clientResp is not None:
                clientResp = clientResp.split("###")[-1].strip()
                log(f"Reply from Client: {clientResp}")
            else:
                log("No reply from Client.")
                clientResp = "[No Reply from Client]"
        else:
            log("No Client connected.")
            clientResp = "[WARN] No Client Connected"
        send_ws(conn, clientResp.encode(), binary=False)
        return
    RECIEVE_COUNTER += 1
    if RECIEVE_COUNTER >= 20:
        RECIEVE_COUNTER = 0
        log("No command from Admin, resetting connection...")
        conn_reset(client_conn, conn)

def client(conn, message):
    if message is None:
        log("[WARN] Tried to send None message to client, skipping.")
        return None

    if type(message) == str:
        send_ws(conn, message.encode(), binary=False)

    resp = recieve(conn)
    return resp

def safe_send_ws(conn, data: bytes, binary=False):
    try:
        send_ws(conn, data, binary=binary)
        return True
    except Exception as e:
        log(f"[WARN] Failed to send data: {e}")
        return False
    
clientConn = None
adminConn = None
lock = threading.Lock()

def is_socket_dead(sock):
    try:
        err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        return err != 0
    except:
        return True


def conn_reset(client_conn, admin_conn):
    global clientConn, adminConn
    if client_conn == clientConn:
        clientConn = None
    if admin_conn == adminConn:
        adminConn = None
    try:
        safe_send_ws(client_conn, b"__DOWNGRADE__")
    except:
        pass
    client_conn.close()
    try:
        safe_send_ws(admin_conn, b"[ERROR]: conn reset by server.\r\nrestart your connection.")
    except:
        pass
    admin_conn.close()



def client_thread(conn, addr):
    global clientConn, adminConn
    try:
        if not websocket_handshake(conn, addr):
            conn.close()
            return

        log(f"Connected: {addr}")

        # Determine if this is a client or admin
        opcode, payload = recv_one_frame(conn, timeout=3)
        if opcode == 0x1:
            response = payload.decode(errors='ignore')
            if response == "__GAIN_ADMIN__":
                adminConn = conn
                log(f"{addr} is admin")
                # admin loop
                while adminConn and adminConn == conn:
                    with lock:
                        if clientConn is None:
                            resp = "[WARN] No Client Connected.\n       Waiting..."
                            opcode, payload = recv_one_frame(conn, timeout=2)
                            if opcode == 0x1:
                                send_ws(conn, resp.encode(), binary=False)
                    try:
                        log(f"waiting for admin commands...")
                        admin(adminConn, clientConn, timeout=20)
                        log(f"iterated admin loop")
                    except Exception as e:
                        log(f"[WARN] Admin disconnected or error: {e}")
                        # notify client
                        if clientConn:
                            safe_send_ws(clientConn, b"__DOWNGRADE__")
                            clientConn.close()
                        adminConn = None
                        clientConn = None
                        return
                return
        # client loop
        clientConn = conn
        log(f"Set Client to: {addr}")
        while clientConn and clientConn == conn:
            time.sleep(1)
        return

    except Exception as e:
        log(f"[WARN] Client thread exception: {e}")
    finally:
        log(f"Client disconnected: {addr}")
        with lock:
            if conn == clientConn:
                clientConn = None
                if adminConn:
                    safe_send_ws(adminConn, b"[WARN] Client disconnected!")
            if conn == adminConn:
                adminConn = None
                if clientConn:
                    safe_send_ws(clientConn, b"__DOWNGRADE__")
                    clientConn.close()
                    clientConn = None
        conn.close()

clientConn = None

def main():
    clear_log()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(2)
    log(f"Server listening on {HOST}:{PORT}")
    while True:
        try:
            conn, addr = sock.accept()
            threading.Thread(target=client_thread, args=(conn, addr), daemon=True).start()
        except Exception as e:
            log(f"[WARN] Accept failed: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()
