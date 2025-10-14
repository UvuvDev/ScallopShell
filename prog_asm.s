.intel_syntax noprefix
endbr64	
xor	ebp, ebp
mov	r9, rdx
pop	rsi
mov	rdx, rsp
and	rsp, 0xfffffffffffffff0
push	rax
push	rsp
xor	r8d, r8d
xor	ecx, ecx
lea	rdi, [rip - 0x36]
call	qword ptr [rip + 0x2f53]
endbr64	
sub	rsp, 8
mov	rax, qword ptr [rip - 0x27]
test	rax, rax
je	0x555555555016
add	rsp, 8
ret	
endbr64	
jmp	0x5555555550c0
lea	rdi, [rip + 0x49]
lea	rsi, [rip + 0x42]
sub	rsi, rdi
mov	rax, rsi
shr	rsi, 0x3f
sar	rax, 3
add	rsi, rax
sar	rsi, 1
je	0x5555555550f8
ret	
endbr64	
push	rbp
mov	rbp, rsp
sub	rsp, 0x10
mov	dword ptr [rbp - 8], 0
mov	dword ptr [rbp - 4], 0
jmp	0x55555555516d
cmp	dword ptr [rbp - 4], 9
jle	0x555555555165
add	dword ptr [rbp - 8], 1
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x555555555165
add	dword ptr [rbp - 8], 1
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x555555555165
add	dword ptr [rbp - 8], 1
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x555555555165
add	dword ptr [rbp - 8], 1
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x555555555165
add	dword ptr [rbp - 8], 1
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x555555555165
add	dword ptr [rbp - 8], 1
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x555555555165
add	dword ptr [rbp - 8], 1
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x555555555165
add	dword ptr [rbp - 8], 1
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x555555555165
add	dword ptr [rbp - 8], 1
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x555555555165
add	dword ptr [rbp - 8], 1
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x555555555165
mov	eax, dword ptr [rbp - 8]
mov	esi, eax
lea	rax, [rip - 0x7b]
mov	rdi, rax
mov	eax, 0
call	0x555555555050
endbr64	
bnd jmp	qword ptr [rip + 0x75]
mov	eax, 0
leave	
ret	
endbr64	
cmp	byte ptr [rip + 0x2f05], 0
jne	0x555555555138
push	rbp
cmp	qword ptr [rip - 0x1e], -1
mov	rbp, rsp
je	0x555555555127
mov	rdi, qword ptr [rip - 0x1a]
call	0x555555555040
endbr64	
bnd jmp	qword ptr [rip - 0x53]
call	0x555555555090
lea	rdi, [rip + 0x79]
lea	rax, [rip + 0x72]
cmp	rax, rdi
je	0x5555555550b8
ret	
mov	byte ptr [rip + 0x2edd], 0
pop	rbp
ret	
endbr64	
sub	rsp, 8
add	rsp, 8
ret	
