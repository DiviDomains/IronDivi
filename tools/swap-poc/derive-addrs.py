# /// script
# requires-python = ">=3.11"
# dependencies = ["pycryptodome==3.23.0"]
# ///
"""Public-key-only address derivation for the swap keys (no secrets).

Usage: printf "<name> <tb1 address> <compressed pubkey hex>\n" | uv run tools/swap-poc/derive-addrs.py
"""
import hashlib, sys
from Crypto.Hash import keccak

CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def polymod(v):
    g=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]; c=1
    for x in v:
        b=c>>25; c=(c&0x1ffffff)<<5^x
        for i in range(5): c^=g[i] if (b>>i)&1 else 0
    return c
def hx(h): return [ord(x)>>5 for x in h]+[0]+[ord(x)&31 for x in h]
def conv(d,f,t,pad=True):
    acc=bits=0; out=[]; m=(1<<t)-1
    for x in d:
        acc=acc<<f|x; bits+=f
        while bits>=t: bits-=t; out.append(acc>>bits&m)
    if pad and bits: out.append(acc<<(t-bits)&m)
    return out
def bech32(hrp,prog):
    d=[0]+conv(prog,8,5); p=polymod(hx(hrp)+d+[0]*6)^1
    return hrp+"1"+"".join(CH[x] for x in d+[p>>5*(5-i)&31 for i in range(6)])
B58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58check(b):
    b+=hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]; n=int.from_bytes(b,"big"); s=""
    while n: n,r=divmod(n,58); s=B58[r]+s
    return "1"*(len(b)-len(b.lstrip(b"\0")))+s
P=2**256-2**32-977
def h160(b): return hashlib.new("ripemd160",hashlib.sha256(b).digest()).digest()
for line in sys.stdin:
    name,btc,pk=line.split(); pkb=bytes.fromhex(pk); h=h160(pkb)
    assert bech32("tb",h)==btc, ("pubkey mismatch",name)
    x=int.from_bytes(pkb[1:],"big"); y=pow((x**3+7)%P,(P+1)//4,P)
    if y%2!=pkb[0]%2: y=P-y
    k=keccak.new(digest_bits=256); k.update(x.to_bytes(32,"big")+y.to_bytes(32,"big"))
    a=k.hexdigest()[-40:]; k2=keccak.new(digest_bits=256); k2.update(a.encode()); hh=k2.hexdigest()
    eth="0x"+"".join(c.upper() if int(hh[i],16)>=8 else c for i,c in enumerate(a))
    print(f"{name}: btc={btc} ltc={bech32('tltc',h)} zec={b58check(bytes([0x1d,0x25])+h)} evm={eth}")
