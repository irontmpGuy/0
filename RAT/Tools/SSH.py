import cmd
import os
import sys  
import requests
import threading
import time
import re
import shutil
import ast
import subprocess
import paramiko
import getpass
import json
import base64

ErrorSign = "\033[33m[!]\033[0m"
Success = "\033[32m[+]\033[0m"
Status = "\033[94m[*]\033[0m"

class SSHInteractiveShell:
    def __init__(self, ssh_client, cmdInstance, term='xterm-256color', width=120, height=40):
        """
        ssh_client: already connected paramiko.SSHClient()
        """
        self.ssh_client = ssh_client
        self.channel = None
        self._reader_thread = None
        self._buf_lock = threading.Lock()
        self._buf = []  # collected remote output chunks
        self._running = False
        self.term = term
        self.width = width
        self.height = height
        self.cmdInstance = cmdInstance

    # ---- helper to drain buffer safely ----
    def _drain_buffer(self):
        with self._buf_lock:
            if not self._buf:
                return ""
            s = "".join(self._buf)
            self._buf = []
            return s

    # ---- background reader thread ----
    def _reader(self):
        try:
            while self._running and self.channel and not self.channel.closed:
                if self.channel.recv_ready():
                    data = self.channel.recv(4096)
                    if not data:
                        time.sleep(0.01)
                        continue
                    text = data.decode(errors='replace')
                    with self._buf_lock:
                        self._buf.append(text)
                else:
                    time.sleep(0.01)
                if self.channel.closed or self.channel.exit_status_ready():
                    break
        except Exception as e:
            print(f"\n{ErrorSign} Reader thread error: {e}")

    # ---- start interactive shell ----
    def start(self):
        if not self.ssh_client:
            raise RuntimeError("SSH client not connected")

        transport = self.ssh_client.get_transport()
        if not transport:
            raise RuntimeError("No SSH transport available")

        self.channel = transport.open_session()
        self.channel.get_pty(term=self.term, width=self.width, height=self.height)
        self.channel.invoke_shell()

        # start background reader
        self._running = True
        self._reader_thread = threading.Thread(target=self._reader, daemon=True)
        self._reader_thread.start()

        # small delay to drain initial prompt/banner
        time.sleep(0.15)
        _ = self._drain_buffer()
        print(f"{Success} Interactive shell opened.\n")

    # ---- send command and return clean output ----
    def send(self, command, timeout=10, waitfor=">"):
        import re, time, sys, uuid

        if not self.channel or self.channel.closed:
            raise RuntimeError("Interactive shell not started or channel closed")

        # clear previous buffer
        _ = self._drain_buffer()

        # helper to clean lines
        def clean_lines(raw):
            lines = raw.splitlines()

            # remove leading blank lines
            while lines and not lines[0].strip():
                lines.pop(0)

            # remove leading echoed command if present
            if lines and lines[0].strip() == command.strip():
                lines.pop(0)

            cleaned = []
            last = None
            marker_re = re.compile(r'__CMD_END_[0-9a-f]+__\d*$')
            exec_echo_re = re.compile(r'^\s*\[.*\]\s*exec:\s*echo', re.IGNORECASE)

            for ln in lines:
                s = ln.strip()
                # skip plain 'echo' lines or marker lines or exec: echo debug lines
                if not s:
                    continue
                if s.startswith("echo "):
                    continue
                if marker_re.search(s):
                    continue
                if exec_echo_re.search(s):
                    continue
                # collapse immediate duplicates (helps with spinner noise)
                if last is not None and s == last:
                    continue
                cleaned.append(ln)
                last = s

            return cleaned

        # WAITFOR mode (interactive programs like msfconsole)
        self.channel.send(command.rstrip() + "\n")

        collected_chunks = []
        joined_buffer = ""
        deadline = time.time() + timeout

        while time.time() < deadline:
            chunk = self._drain_buffer()
            if chunk:
                # print live
                sys.stdout.write(chunk)
                sys.stdout.flush()

                collected_chunks.append(chunk)
                joined_buffer += chunk

                # check for waitfor pattern in the whole buffer
                ANSI_RE = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*(?:\x07)?|\x1b.')
                cleaned = ANSI_RE.sub('', joined_buffer).replace('\r\n', '\n').replace('\r', '\n')
                if waitfor != ">":
                    if waitfor in cleaned:
                        break
                else:
                    if cleaned.strip().endswith(waitfor) or cleaned.strip().endswith("$"):

                        break
            time.sleep(0.02)

        raw = "".join(collected_chunks)
        lines = clean_lines(raw)

        output = "\n".join(lines).split(waitfor)[0]
        # split lines and clean: 
        return "\n".join(output).strip()
        # Try to find the prompt line (last line matching waitfor) and set cmd prompt
        # We'll use the waitfor regex to find the last occurrence
            

    # ---- stop shell ----
    def stop(self):
        self._running = False
        try:
            if self.channel:
                self.channel.close()
        except Exception:
            pass
        print(f"{Success} Interactive shell closed.")

class ssh_shell(cmd.Cmd):

    def __init__(self, host, user, port=22):
        super().__init__()
        self.ssh_client = None
        self.ssh_host = host
        self.ssh_port = port
        self.ssh_user = user

    def ssh_connect(self):
        """Connect to SSH server"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            password = getpass.getpass("ssh password: ")
            self.ssh_client.connect(self.ssh_host, port=self.ssh_port, username=self.ssh_user, password=password)
            print(f"{Success} Connected to {self.ssh_host}")
        except Exception as e:
            print(f"{ErrorSign} SSH connection failed: {e}")
            print(f"{ErrorSign} Try \"options\" to set a host")
    
    def ssh_shell(self):
        if not self.ssh_client:
            self.ssh_connect()
            if not self.ssh_client:
                print(f"{ErrorSign} Not connected. Use 'connect' first.")
                return

        try:
            # store on self so it's not garbage-collected
            self.shell = SSHInteractiveShell(self.ssh_client, self)
            self.shell.start()

            # small pause to let the remote prompt settle (you can lower or remove if unnecessary)
            time.sleep(0.15)

            # send whoami and print the real command output
        except Exception as e:
            print(f"{ErrorSign} Interactive shell failed: {e}")

def load_steps_from_b64_arg(index=4, debug=False):
    """Expect base64-encoded JSON at sys.argv[index].
    Handles double-encoded JSON (JSON string containing JSON), and falls back to ast.literal_eval.
    Returns a Python list (steps) or raises ValueError."""
    if len(sys.argv) <= index:
        return []

    b64 = sys.argv[index]
    if debug:
        print("[DEBUG] got base64 argv:", repr(b64[:120]) + ("..." if len(b64) > 120 else ""))

    try:
        decoded_bytes = base64.b64decode(b64)
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")

    try:
        decoded = decoded_bytes.decode("utf-8", errors="replace").strip()
    except Exception as e:
        raise ValueError(f"UTF-8 decode failed: {e}")

    if debug:
        print("[DEBUG] decoded (preview):", repr(decoded[:500]) + ("..." if len(decoded) > 500 else ""))

    # 1) Try direct JSON parse
    try:
        parsed = json.loads(decoded)
    except Exception as e_json:
        json_err = e_json
        parsed = None

    # 2) If parsed is a string, try json.loads again (handles double-encoded JSON)
    if isinstance(parsed, str):
        if debug:
            print("[DEBUG] top-level JSON is a string; trying to json.loads() it again")
        try:
            parsed2 = json.loads(parsed)
            parsed = parsed2
        except Exception as e2:
            # leave parsed as the string and fall through to fallback
            if debug:
                print("[DEBUG] second json.loads failed:", e2)

    # 3) If still not parsed, try ast.literal_eval (accepts Python literal lists)
    if parsed is None:
        try:
            maybe = ast.literal_eval(decoded)
            parsed = maybe
        except Exception as e_ast:
            ast_err = e_ast
            parsed = None

    # 4) Final checks: must be list-like
    if not isinstance(parsed, (list, tuple)):
        raise ValueError(
            "Parsed steps is not a list/tuple.\n"
            f"json.loads error (first try): {locals().get('json_err', 'none')}\n"
            f"ast.literal_eval error: {locals().get('ast_err', 'none')}\n"
            f"Decoded preview: {repr(decoded[:300])}{'...' if len(decoded) > 300 else ''}"
        )

    # convert to list and return
    return list(parsed)


def main():
    # basic usage: host,user,port are argv[1..3], encoded steps at argv[4]
    if len(sys.argv) < 4:
        print("Usage: python SSH.py <host> <user> <port> [base64_json_commands]")
        sys.exit(1)

    host = sys.argv[1]
    user = sys.argv[2]
    port = sys.argv[3]

    try:
        steps = load_steps_from_b64_arg(4)
    except Exception as e:
        print("[!] Failed to load steps:", e)
        steps = []

    print(f" {Status} Host:", host, "User:", user, "Port:", port)

    shell = ssh_shell(host, user, port)
    shell.ssh_connect()

    shell.ssh_shell()

    for i in steps:
        if len(i) == 1:
            shell.shell.send(i[0])
        elif len(i) == 2:
            shell.shell.send(i[0], i[1])
        elif len(i) == 3:
            shell.shell.send(i[0], i[1], i[2])
    
    while True:
        try:
            command = input()
            shell.shell.send(command, 9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999)
        except KeyboardInterrupt:
            shell.shell.send("\x03")


if __name__ == "__main__":
    main()


