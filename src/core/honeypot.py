import socket
import datetime
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
log_file = os.path.join(BASE_DIR, "logs", "honeypot.log")
attackers_file = os.path.join(BASE_DIR, "state", "attackers.txt")

HONEY_PORT = 2222

def log(msg):
    ts = datetime.datetime.now().isoformat()
    with open(log_file, "a") as f:
        f.write(f"{ts} {msg}\n")

def record_attacker(ip):
    with open(attackers_file, "a") as f:
        f.write(f"{ip}\n")

def start_honeypot():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", HONEY_PORT))
    s.listen(5)
    log(f"[START] Honeypot running on port {HONEY_PORT}")

    while True:
        client, addr = s.accept()
        ip = addr[0]
        log(f"[HIT] Connection from {ip}")
        record_attacker(ip)

        # Fake SSH banner
        client.send(b"SSH-2.0-OpenSSH_8.2\r\n")
        client.close()

if __name__ == "__main__":
    start_honeypot()
