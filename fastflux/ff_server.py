import socket
import random
from dnslib import DNSRecord, RR, A, QTYPE



# Auto-detect your IP
IP = "127.0.0.1"
PORT = 53  

def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    print(f"[🔥] Rogue Fast Flux DNS Server listening on {IP}:{PORT}")
    print("[*] Waiting for queries...\n")

    # 👇 Python gets trapped in this loop forever!
    while True:
        data, addr = sock.recvfrom(512)
        request = DNSRecord.parse(data)
        reply = request.reply()
        
        qname = request.q.qname
        
        for _ in range(random.randint(1, 3)):
            fake_ip = f"{random.randint(1, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(fake_ip), ttl=random.randint(10, 60)))
            
        sock.sendto(reply.pack(), addr)
        print(f"[+] Sent Fast Flux response to {addr[0]}:{addr[1]} for domain: {qname}")

if __name__ == "__main__":
    start_server()