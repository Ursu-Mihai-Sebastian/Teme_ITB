import hashlib
from Crypto.Util.number import bytes_to_long

# Task 1
nf = "Ursu"
prn = "Mihai"

# hash interior
ih = hashlib.sha256(b"Blockchain").hexdigest()

p = f"{nf}.{prn}.{ih}"

# hash final
r = hashlib.sha256(p.encode("utf-8")).hexdigest()

print(f"Blockchain: {ih}")
print(f"Final: {r}\n")

# Task 2
print("Task 2")

htarget = "8ec47631827329eb114714a20d9b3eeb8a9a4293bd5d6823af0632e8d4f30dfa"
fila = "rockyou.txt"

print(f"Hash tinta: {htarget}")
print(f"Cauta in {fila}")

gasit = False

with open(fila, "r", encoding="latin-1", errors="ignore") as file_handle:
    for line_num, line in enumerate(file_handle, 1):
        c = line.strip()
        c_hash = hashlib.sha256(c.encode("utf-8")).hexdigest()

        if c_hash == htarget:
            print(f"Parola la linia {line_num}: {c}")
            gasit = True
            break

if not gasit:
    print("Parola nu a fost gasita.")

# Task 3 Public Keys

p = 17
q = 23
e = 65537
m = 12

N = p * q
c = pow(m, e, N)

print()
print("Task 3:", c)


# Task 4 Private Keys

p = 857504083339712752489993810777
q = 1029224947942998075080348647219
e = 65537

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

print("Task 4:", d)

# Task 5 RSA Decryption

N = 882564595536224140639625987659416029426239230804614613279163
c = 77578995801157823671636298847186723593814843845525223303932

m = pow(c, d, N)

print("Task 5:", m)

# Task 6 RSA Signatures

N = 15216583654836731327639981224133918855895948374072384050848479908982286890731769486609085918857664046075375253168955058743185664390273058074450390236774324903305663479046566232967297765731625328029814055635316002591227570271271445226094919864475407884459980489638001092788574811554149774028950310695112688723853763743238753349782508121985338746755237819373178699343135091783992299561827389745132880022259873387524273298850340648779897909381979714026837172003953221052431217940632552930880000919436507245150726543040714721553361063311954285289857582079880295199632757829525723874753306371990452491305564061051059885803
d = 11175901210643014262548222473449533091378848269490518850474399681690547281665059317155831692300453197335735728459259392366823302405685389586883670043744683993709123180805154631088513521456979317628012721881537154107239389466063136007337120599915456659758559300673444689263854921332185562706707573660658164991098457874495054854491474065039621922972671588299315846306069845169959451250821044417886630346229021305410340100401530146135418806544340908355106582089082980533651095594192031411679866134256418292249592135441145384466261279428795408721990564658703903787956958168449841491667690491585550160457893350536334242689

# Semnatura
msg = b"crypto{Immut4ble_m3ssag1ng}"
msg_hash = hashlib.sha256(msg).digest()

h_int = bytes_to_long(msg_hash)
semnatura = pow(h_int, d, N)

print("Task 6:", semnatura)


# Task 7 Point Negation

print()

p = 9739
x = 8045
y = 6936

y_neg = (-y) % p

print(f"Task 7: crypto{{{x},{y_neg}}}")

# Task 8 Point Addition

p = 9739
a = 497

p = 9739
a = 497

def add(P, Q):
    # (a) If P = O, then P + Q = Q
    if P is None:
        return Q

    # (b) If Q = O, then P + Q = P
    if Q is None:
        return P

    # (c) P = (x1, y1) and Q = (x2, y2)
    x1, y1 = P
    x2, y2 = Q

    # (d) If x1 = x2 and y1 = -y2, then P + Q = O
    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    # (e) panta lambdei
    if P != Q:  # (e1) P != Q
        lam = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    else:       # (e2) P == Q
        lam = ((3 * x1**2 + a) * pow(2 * y1, -1, p)) % p

    # (f) x3 = lambda^2 - x1 - x2
    x3 = (lam**2 - x1 - x2) % p

    # (h) y3 = lambda * (x1 - x3) - y1
    y3 = (lam * (x1 - x3) - y1) % p

    # (i) P + Q = (x3, y3)
    return (x3, y3)

P = (493, 5564)
Q = (1539, 4742)
R = (4403, 5202)

S = add(add(add(P, P), Q), R)

print(f"Task 8: crypto{{{S[0]},{S[1]}}}")
