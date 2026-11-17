import hashlib, itertools, re, socket, time

HOST, PORT = "202.61.227.83", 31337
CHARS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
HASHES = {"sha256": hashlib.sha256, "md5": hashlib.md5, "keccak": hashlib.sha3_256}

def solve(name, suffix, target_hex):
    h = HASHES[name]
    target = bytes.fromhex(target_hex)
    suf = suffix.encode()
    for p in itertools.permutations(CHARS, 20 - len(suffix)):
        if h(bytes(p) + suf).digest() == target:
            return bytes(p).decode()

s = socket.create_connection((HOST, PORT), timeout=15)
s.settimeout(600)
f = s.makefile("rw", buffering=1, encoding="utf-8", newline="\n")

for rnd in range(1, 16):
    line = f.readline()
    while line and not re.match(r"^\w+\(xxxx \+ ", line):
        line = f.readline()
    if not line:
        print("conexiune inchisa"); break
    name, suf, tgt = re.match(r"^(\w+)\(xxxx \+ (\w+)\) == ([0-9a-f]+)", line).groups()
    f.readline()
    ans = solve(name, suf, tgt)
    print(f"Runda {rnd}: {name} -> {ans}")
    f.write(ans + "\n"); f.flush()

for line in f:
    if line.strip() and line.strip() != ans:
        print(line.strip())