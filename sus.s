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
