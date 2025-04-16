.intel_syntax noprefix
xor	ebp, ebp
mov	r9, rdx
pop	rsi
mov	rdx, rsp
and	rsp, 0xfffffffffffffff0
push	rax
push	rsp
xor	r8d, r8d
xor	ecx, ecx
lea	rdi, [rip - 0x32]
call	qword ptr [rip + 0x2edf]
sub	rsp, 8
mov	rax, qword ptr [rip - 0x3b]
test	rax, rax
je	0x555555555012
add	rsp, 8
ret	
endbr64	
jmp	0x555555555120
lea	rdi, [rip + 0x29]
lea	rsi, [rip + 0x22]
sub	rsi, rdi
mov	rax, rsi
shr	rsi, 0x3f
sar	rax, 3
add	rsi, rax
sar	rsi, 1
je	0x555555555158
ret	
push	rbp
mov	rbp, rsp
sub	rsp, 0x20
lea	rax, [rip + 0x50]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
push	3
jmp	0x555555555020
push	qword ptr [rip + 0x2fca]
jmp	qword ptr [rip + 0x2fcc]
mov	edi, 0x28
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
push	6
jmp	0x555555555020
push	qword ptr [rip + 0x2fca]
jmp	qword ptr [rip + 0x2fcc]
mov	qword ptr [rbp - 0x10], rax
lea	rax, [rip + 0x52]
