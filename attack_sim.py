"""
🚨 Network Attack Simulator — Multi-Attack Suite
==================================================
Simulates different types of network attacks to test the IDS dashboard.
Includes attacks that trigger the ML model and a normal traffic generator.

MUST be run from an Administrator PowerShell:
    python attack_sim.py

Choose an attack type from the interactive menu. Press Ctrl+C to stop any attack.
"""

import sys
import random
import time
import argparse

try:
    from scapy.all import IP, TCP, send, conf
except ImportError:
    print("❌ Scapy is not installed. Run: pip install scapy")
    sys.exit(1)

# Suppress Scapy verbosity
conf.verb = 0

TARGET_IP = "127.0.0.1"


# ============================================================================
# RULE-DETECTED ATTACKS  (trigger the rule-based engine)
# ============================================================================

def syn_flood():
    """
    🔴 SYN FLOOD — Classic volumetric DoS.
    Detected by: RULES (SYN/ACK ratio anomaly)
    """
    target_port = random.randint(1024, 65535)
    burst_size = 100

    _banner("SYN FLOOD", "red",
            f"Target: {TARGET_IP}:{target_port}",
            "Method: Blast TCP SYN packets, random source ports",
            "Detected by: Rules → SYN/ACK ratio anomaly + volume spike")

    total = 0
    t0 = time.time()
    try:
        while True:
            pkts = [
                IP(dst=TARGET_IP) / TCP(
                    sport=random.randint(1024, 65535),
                    dport=target_port, flags="S",
                    seq=random.randint(0, 2**32 - 1))
                for _ in range(burst_size)
            ]
            send(pkts, verbose=False)
            total += burst_size
            _progress("SYN", total, t0)
            time.sleep(0.01)
    except KeyboardInterrupt:
        _summary(total, t0)


def port_scan():
    """
    🟡 PORT SCAN — nmap-style sequential service discovery.
    Detected by: RULES (many unique destination ports)
    """
    start_port = random.randint(1, 1000)

    _banner("PORT SCAN", "yellow",
            f"Target: {TARGET_IP}",
            f"Ports: {start_port}–{start_port + 1000}",
            "Method: SYN to each port (like nmap -sS)",
            "Detected by: Rules → unique dest port count > 15")

    total = 0
    t0 = time.time()
    sport = random.randint(40000, 60000)
    try:
        while True:
            for port in range(start_port, start_port + 1000):
                send(IP(dst=TARGET_IP) / TCP(sport=sport, dport=port, flags="S"),
                     verbose=False)
                total += 1
                if total % 50 == 0:
                    _progress("SCAN", total, t0, extra=f"port={port}")
            print(f"\n  🔄 Completed range, restarting...")
    except KeyboardInterrupt:
        _summary(total, t0)


def xmas_tree():
    """
    🎄 CHRISTMAS TREE — Abnormal TCP flags (FIN+PSH+URG).
    Detected by: RULES (flag anomaly detection)
    """
    target_port = random.randint(1024, 65535)

    _banner("CHRISTMAS TREE ATTACK", "green",
            f"Target: {TARGET_IP}:{target_port}",
            "Method: TCP packets with FIN+PSH+URG flags all set",
            "Detected by: Rules → abnormal flag combination count")

    total = 0
    t0 = time.time()
    try:
        while True:
            pkts = [
                IP(dst=TARGET_IP) / TCP(
                    sport=random.randint(1024, 65535),
                    dport=target_port, flags="FPU",
                    seq=random.randint(0, 2**32 - 1))
                for _ in range(50)
            ]
            send(pkts, verbose=False)
            total += 50
            _progress("XMAS", total, t0)
            time.sleep(0.02)
    except KeyboardInterrupt:
        _summary(total, t0)


# ============================================================================
# ML-MODEL-DETECTED ATTACKS  (trigger the Random Forest classifier)
# ============================================================================

def ssh_brute_force():
    """
    🟣 SSH BRUTE FORCE — Mimics rapid SSH login attempts.
    Detected by: ML MODEL (port 22, many bidirectional packets, small payloads)

    The ML model learned from CICIDS2017 that flows to port 22 with many
    forward AND backward packets and small payloads are SSH brute-force attacks.
    Each simulated "login attempt" is a flow with:
      - SYN + multiple data packets (small payload simulating password attempts)
      - ACK packets (simulating server responses)
    """
    target_port = 22
    attempts_per_burst = 20

    _banner("SSH BRUTE FORCE", "purple",
            f"Target: {TARGET_IP}:{target_port} (SSH)",
            f"Method: Simulated login attempts with bidirectional traffic",
            f"Burst: {attempts_per_burst} 'login attempts' per round",
            "Detected by: ML Model → matches CICIDS2017 SSH-Patator pattern")

    total = 0
    t0 = time.time()
    try:
        while True:
            for _ in range(attempts_per_burst):
                sport = random.randint(10000, 60000)
                flow_pkts = []

                # SYN (connection initiation)
                flow_pkts.append(
                    IP(dst=TARGET_IP) / TCP(sport=sport, dport=target_port, flags="S"))

                # Multiple forward packets (login attempt data — small payloads)
                for i in range(random.randint(15, 25)):
                    flow_pkts.append(
                        IP(dst=TARGET_IP) / TCP(
                            sport=sport, dport=target_port, flags="PA",
                            seq=1000 + i * 50)
                        / (b"USER admin\r\nPASS " + bytes(str(random.randint(100000, 999999)), "ascii") + b"\r\n"))

                # Backward packets (server responses — simulated with small ACKs)
                for i in range(random.randint(10, 20)):
                    flow_pkts.append(
                        IP(src=TARGET_IP, dst=TARGET_IP) / TCP(
                            sport=target_port, dport=sport, flags="PA",
                            seq=2000 + i * 30)
                        / b"Permission denied\r\n")

                send(flow_pkts, verbose=False)
                total += len(flow_pkts)

            _progress("SSH", total, t0, extra=f"{attempts_per_burst} attempts/burst")
            time.sleep(0.1)
    except KeyboardInterrupt:
        _summary(total, t0)


def ftp_brute_force():
    """
    🟤 FTP BRUTE FORCE — Mimics rapid FTP login attempts.
    Detected by: ML MODEL (port 21, many bidirectional packets, small payloads)

    Similar to SSH brute force — the model flags flows to port 21 with
    many packets in both directions and small payload sizes.
    """
    target_port = 21
    attempts_per_burst = 20

    _banner("FTP BRUTE FORCE", "brown",
            f"Target: {TARGET_IP}:{target_port} (FTP)",
            "Method: Simulated FTP login attempts with bidirectional traffic",
            f"Burst: {attempts_per_burst} 'login attempts' per round",
            "Detected by: ML Model → matches CICIDS2017 FTP-Patator pattern")

    total = 0
    t0 = time.time()
    try:
        while True:
            for _ in range(attempts_per_burst):
                sport = random.randint(10000, 60000)
                flow_pkts = []

                # SYN
                flow_pkts.append(
                    IP(dst=TARGET_IP) / TCP(sport=sport, dport=target_port, flags="S"))

                # Forward: FTP commands
                for i in range(random.randint(20, 35)):
                    flow_pkts.append(
                        IP(dst=TARGET_IP) / TCP(
                            sport=sport, dport=target_port, flags="PA",
                            seq=1000 + i * 40)
                        / (b"USER admin\r\nPASS " + bytes(str(random.randint(100000, 999999)), "ascii") + b"\r\n"))

                # Backward: server responses
                for i in range(random.randint(15, 25)):
                    flow_pkts.append(
                        IP(src=TARGET_IP, dst=TARGET_IP) / TCP(
                            sport=target_port, dport=sport, flags="PA",
                            seq=2000 + i * 30)
                        / b"530 Login incorrect\r\n")

                send(flow_pkts, verbose=False)
                total += len(flow_pkts)

            _progress("FTP", total, t0, extra=f"{attempts_per_burst} attempts/burst")
            time.sleep(0.1)
    except KeyboardInterrupt:
        _summary(total, t0)


# ============================================================================
# NORMAL TRAFFIC  (should NOT be flagged — demonstrates no false positives)
# ============================================================================

def normal_traffic():
    """
    🟢 NORMAL TRAFFIC GENERATOR — Simulates legitimate HTTP/HTTPS browsing.
    Expected result: Dashboard stays GREEN (✅ BENIGN)

    Generates realistic-looking TCP flows:
      - Proper SYN → ACK handshake pattern
      - Normal payload sizes (HTTP requests ~200-500 bytes, responses ~800-1500)
      - Standard ports (80, 443, 8080)
      - Low volume, varied timing
    """
    ports = [80, 443, 8080, 8443, 3000]

    _banner("NORMAL TRAFFIC", "green",
            f"Target: {TARGET_IP}",
            f"Ports: {ports}",
            "Method: Realistic HTTP/HTTPS-style flows",
            "Expected: Dashboard should stay ✅ BENIGN (no false positives)")

    total = 0
    t0 = time.time()
    try:
        while True:
            # Simulate 1-3 "web page loads" per cycle
            for _ in range(random.randint(1, 3)):
                dport = random.choice(ports)
                sport = random.randint(49152, 65535)
                flow_pkts = []

                # SYN (1 pkt)
                flow_pkts.append(
                    IP(dst=TARGET_IP) / TCP(
                        sport=sport, dport=dport, flags="S"))

                # SYN-ACK response (1 pkt)
                flow_pkts.append(
                    IP(src=TARGET_IP, dst=TARGET_IP) / TCP(
                        sport=dport, dport=sport, flags="SA"))

                # ACK (1 pkt) — handshake complete
                flow_pkts.append(
                    IP(dst=TARGET_IP) / TCP(
                        sport=sport, dport=dport, flags="A"))

                # HTTP Request (1-3 forward data pkts, 200-500 bytes each)
                for i in range(random.randint(1, 3)):
                    payload = b"GET /page" + bytes(str(random.randint(1, 100)), "ascii") + b" HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n"
                    flow_pkts.append(
                        IP(dst=TARGET_IP) / TCP(
                            sport=sport, dport=dport, flags="PA",
                            seq=1000 + i * 500)
                        / payload)

                # HTTP Response (1-3 backward data pkts, 800-1500 bytes each)
                for i in range(random.randint(1, 3)):
                    payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>" + b"x" * random.randint(800, 1400) + b"</body></html>"
                    flow_pkts.append(
                        IP(src=TARGET_IP, dst=TARGET_IP) / TCP(
                            sport=dport, dport=sport, flags="PA",
                            seq=2000 + i * 1500)
                        / payload)

                # FIN-ACK (connection close)
                flow_pkts.append(
                    IP(dst=TARGET_IP) / TCP(
                        sport=sport, dport=dport, flags="FA"))
                flow_pkts.append(
                    IP(src=TARGET_IP, dst=TARGET_IP) / TCP(
                        sport=dport, dport=sport, flags="FA"))

                send(flow_pkts, verbose=False)
                total += len(flow_pkts)

            _progress("NORMAL", total, t0, extra="should be BENIGN")

            # Normal browsing pace: 0.5–2 seconds between page loads
            time.sleep(random.uniform(0.5, 2.0))

    except KeyboardInterrupt:
        _summary(total, t0)


# ============================================================================
# Helpers
# ============================================================================

def _banner(title, color, *lines):
    print(f"\n{'='*60}")
    print(f"  🚨 ATTACK: {title}")
    print(f"{'='*60}")
    for line in lines:
        print(f"  {line}")
    print(f"  Press Ctrl+C to stop")
    print(f"{'='*60}\n")


def _progress(tag, total, t0, extra=""):
    elapsed = time.time() - t0
    rate = total / elapsed if elapsed > 0 else 0
    extra_str = f"  | {extra}" if extra else ""
    print(
        f"\r  📤 [{tag}] Sent: {total:>8,} pkts  "
        f"| Rate: {rate:>8,.0f} pkt/s  "
        f"| Elapsed: {elapsed:>6.1f}s{extra_str}",
        end="", flush=True,
    )


def _summary(total, t0):
    elapsed = time.time() - t0
    print(f"\n\n{'='*60}")
    print(f"  🛑 Stopped.")
    print(f"  Total packets sent: {total:,}")
    print(f"  Duration:           {elapsed:.1f}s")
    if elapsed > 0:
        print(f"  Average rate:       {total / elapsed:,.0f} pkt/s")
    print(f"{'='*60}")


# ============================================================================
# Menu
# ============================================================================

ATTACKS = {
    "1": ("🔴 SYN Flood              [Rules]", syn_flood),
    "2": ("🟡 Port Scan              [Rules]", port_scan),
    "3": ("🎄 Christmas Tree Attack  [Rules]", xmas_tree),
    "4": ("🟣 SSH Brute Force        [ML Model]", ssh_brute_force),
    "5": ("🟤 FTP Brute Force        [ML Model]", ftp_brute_force),
    "6": ("🟢 Normal Traffic         [Should be BENIGN]", normal_traffic),
}


def show_menu():
    print(f"\n{'='*60}")
    print(f"  🚨 NETWORK ATTACK SIMULATOR")
    print(f"{'='*60}")
    print(f"  Target: {TARGET_IP}\n")
    print(f"  ── Rule-Detected Attacks ──")
    for k in ["1", "2", "3"]:
        print(f"    [{k}] {ATTACKS[k][0]}")
    print(f"\n  ── ML-Model-Detected Attacks ──")
    for k in ["4", "5"]:
        print(f"    [{k}] {ATTACKS[k][0]}")
    print(f"\n  ── Verification ──")
    print(f"    [6] {ATTACKS['6'][0]}")
    print(f"\n    [q] Quit\n")
    return input("  Select > ").strip().lower()


def main():
    parser = argparse.ArgumentParser(description="Network Attack Simulator")
    parser.add_argument("--attack", "-a", choices=list(ATTACKS.keys()),
                        help="Run directly: 1=SYN 2=Scan 3=Xmas 4=SSH 5=FTP 6=Normal")
    args = parser.parse_args()

    if args.attack:
        ATTACKS[args.attack][1]()
        return

    while True:
        choice = show_menu()
        if choice == "q":
            print("  Bye!")
            break
        elif choice in ATTACKS:
            ATTACKS[choice][1]()
        else:
            print("  ❌ Invalid choice.")


if __name__ == "__main__":
    main()
