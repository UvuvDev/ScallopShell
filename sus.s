.intel_syntax noprefix
xor	ebp, ebp
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
mov	rdi, rax
call	0x555555555050
jmp	qword ptr [rip + 0x2fba]
push	2
jmp	0x555555555020
push	qword ptr [rip + 0x2fca]
jmp	qword ptr [rip + 0x2fcc]
mov	edi, 0
call	0x555555555080
jmp	qword ptr [rip + 0x2fa2]
push	5
jmp	0x555555555020
push	qword ptr [rip + 0x2fca]
jmp	qword ptr [rip + 0x2fcc]
lea	rax, [rip - 0x67]
lea	rdx, [rip - 0x6e]
cmp	dword ptr [rip - 0x4b74], 0x7fffffff
cmove	rax, rdx
mov	rax, qword ptr [rax + 0x20]
test	rdi, rdi
je	0x7ffff7fc1c08
ret	
mov	edi, eax
call	0x555555555070
jmp	qword ptr [rip + 0x2faa]
push	4
jmp	0x555555555020
push	qword ptr [rip + 0x2fca]
jmp	qword ptr [rip + 0x2fcc]
mov	dword ptr [rbp - 4], 0
jmp	0x555555555248
cmp	dword ptr [rbp - 4], 9
jle	0x5555555551fc
call	0x5555555550a0
jmp	qword ptr [rip + 0x2f92]
push	7
jmp	0x555555555020
push	qword ptr [rip + 0x2fca]
jmp	qword ptr [rip + 0x2fcc]
movsxd	rdx, eax
imul	rdx, rdx, 0x21
shr	rdx, 0x20
add	edx, eax
sar	edx, 9
mov	ecx, eax
sar	ecx, 0x1f
sub	edx, ecx
imul	ecx, edx, 0x3e7
sub	eax, ecx
mov	edx, eax
lea	eax, [rdx + 1]
mov	dword ptr [rbp - 0x14], eax
mov	eax, dword ptr [rbp - 4]
cdqe	
lea	rdx, [rax*4 - 1]
mov	rax, qword ptr [rbp - 0x10]
add	rdx, rax
mov	eax, dword ptr [rbp - 0x14]
mov	dword ptr [rdx], eax
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x5555555551fc
call	0x5555555550a0
jmp	qword ptr [rip + 0x2f92]
movsxd	rdx, eax
imul	rdx, rdx, 0x21
shr	rdx, 0x20
add	edx, eax
sar	edx, 9
mov	ecx, eax
sar	ecx, 0x1f
sub	edx, ecx
imul	ecx, edx, 0x3e7
sub	eax, ecx
mov	edx, eax
lea	eax, [rdx + 1]
mov	dword ptr [rbp - 0x14], eax
mov	eax, dword ptr [rbp - 4]
cdqe	
lea	rdx, [rax*4 - 1]
mov	rax, qword ptr [rbp - 0x10]
add	rdx, rax
mov	eax, dword ptr [rbp - 0x14]
mov	dword ptr [rdx], eax
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x5555555551fc
call	0x5555555550a0
jmp	qword ptr [rip + 0x2f92]
movsxd	rdx, eax
imul	rdx, rdx, 0x21
shr	rdx, 0x20
add	edx, eax
sar	edx, 9
mov	ecx, eax
sar	ecx, 0x1f
sub	edx, ecx
imul	ecx, edx, 0x3e7
sub	eax, ecx
mov	edx, eax
lea	eax, [rdx + 1]
mov	dword ptr [rbp - 0x14], eax
mov	eax, dword ptr [rbp - 4]
cdqe	
lea	rdx, [rax*4 - 1]
mov	rax, qword ptr [rbp - 0x10]
add	rdx, rax
mov	eax, dword ptr [rbp - 0x14]
mov	dword ptr [rdx], eax
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x5555555551fc
call	0x5555555550a0
jmp	qword ptr [rip + 0x2f92]
movsxd	rdx, eax
imul	rdx, rdx, 0x21
shr	rdx, 0x20
add	edx, eax
sar	edx, 9
mov	ecx, eax
sar	ecx, 0x1f
sub	edx, ecx
imul	ecx, edx, 0x3e7
sub	eax, ecx
mov	edx, eax
lea	eax, [rdx + 1]
mov	dword ptr [rbp - 0x14], eax
mov	eax, dword ptr [rbp - 4]
cdqe	
lea	rdx, [rax*4 - 1]
mov	rax, qword ptr [rbp - 0x10]
add	rdx, rax
mov	eax, dword ptr [rbp - 0x14]
mov	dword ptr [rdx], eax
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x5555555551fc
call	0x5555555550a0
jmp	qword ptr [rip + 0x2f92]
movsxd	rdx, eax
imul	rdx, rdx, 0x21
shr	rdx, 0x20
add	edx, eax
sar	edx, 9
mov	ecx, eax
sar	ecx, 0x1f
sub	edx, ecx
imul	ecx, edx, 0x3e7
sub	eax, ecx
mov	edx, eax
lea	eax, [rdx + 1]
mov	dword ptr [rbp - 0x14], eax
mov	eax, dword ptr [rbp - 4]
cdqe	
lea	rdx, [rax*4 - 1]
mov	rax, qword ptr [rbp - 0x10]
add	rdx, rax
mov	eax, dword ptr [rbp - 0x14]
mov	dword ptr [rdx], eax
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x5555555551fc
call	0x5555555550a0
jmp	qword ptr [rip + 0x2f92]
movsxd	rdx, eax
imul	rdx, rdx, 0x21
shr	rdx, 0x20
add	edx, eax
sar	edx, 9
mov	ecx, eax
sar	ecx, 0x1f
sub	edx, ecx
imul	ecx, edx, 0x3e7
sub	eax, ecx
mov	edx, eax
lea	eax, [rdx + 1]
mov	dword ptr [rbp - 0x14], eax
mov	eax, dword ptr [rbp - 4]
cdqe	
lea	rdx, [rax*4 - 1]
mov	rax, qword ptr [rbp - 0x10]
add	rdx, rax
mov	eax, dword ptr [rbp - 0x14]
mov	dword ptr [rdx], eax
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x5555555551fc
call	0x5555555550a0
jmp	qword ptr [rip + 0x2f92]
movsxd	rdx, eax
imul	rdx, rdx, 0x21
shr	rdx, 0x20
add	edx, eax
sar	edx, 9
mov	ecx, eax
sar	ecx, 0x1f
sub	edx, ecx
imul	ecx, edx, 0x3e7
sub	eax, ecx
mov	edx, eax
lea	eax, [rdx + 1]
mov	dword ptr [rbp - 0x14], eax
mov	eax, dword ptr [rbp - 4]
cdqe	
lea	rdx, [rax*4 - 1]
mov	rax, qword ptr [rbp - 0x10]
add	rdx, rax
mov	eax, dword ptr [rbp - 0x14]
mov	dword ptr [rdx], eax
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x5555555551fc
call	0x5555555550a0
jmp	qword ptr [rip + 0x2f92]
movsxd	rdx, eax
imul	rdx, rdx, 0x21
shr	rdx, 0x20
add	edx, eax
sar	edx, 9
mov	ecx, eax
sar	ecx, 0x1f
sub	edx, ecx
imul	ecx, edx, 0x3e7
sub	eax, ecx
mov	edx, eax
lea	eax, [rdx + 1]
mov	dword ptr [rbp - 0x14], eax
mov	eax, dword ptr [rbp - 4]
cdqe	
lea	rdx, [rax*4 - 1]
mov	rax, qword ptr [rbp - 0x10]
add	rdx, rax
mov	eax, dword ptr [rbp - 0x14]
mov	dword ptr [rdx], eax
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x5555555551fc
call	0x5555555550a0
jmp	qword ptr [rip + 0x2f92]
movsxd	rdx, eax
imul	rdx, rdx, 0x21
shr	rdx, 0x20
add	edx, eax
sar	edx, 9
mov	ecx, eax
sar	ecx, 0x1f
sub	edx, ecx
imul	ecx, edx, 0x3e7
sub	eax, ecx
mov	edx, eax
lea	eax, [rdx + 1]
mov	dword ptr [rbp - 0x14], eax
mov	eax, dword ptr [rbp - 4]
cdqe	
lea	rdx, [rax*4 - 1]
mov	rax, qword ptr [rbp - 0x10]
add	rdx, rax
mov	eax, dword ptr [rbp - 0x14]
mov	dword ptr [rdx], eax
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x5555555551fc
call	0x5555555550a0
jmp	qword ptr [rip + 0x2f92]
movsxd	rdx, eax
imul	rdx, rdx, 0x21
shr	rdx, 0x20
add	edx, eax
sar	edx, 9
mov	ecx, eax
sar	ecx, 0x1f
sub	edx, ecx
imul	ecx, edx, 0x3e7
sub	eax, ecx
mov	edx, eax
lea	eax, [rdx + 1]
mov	dword ptr [rbp - 0x14], eax
mov	eax, dword ptr [rbp - 4]
cdqe	
lea	rdx, [rax*4 - 1]
mov	rax, qword ptr [rbp - 0x10]
add	rdx, rax
mov	eax, dword ptr [rbp - 0x14]
mov	dword ptr [rdx], eax
add	dword ptr [rbp - 4], 1
cmp	dword ptr [rbp - 4], 9
jle	0x5555555551fc
mov	dword ptr [rbp - 8], 0
jmp	0x555555555290
cmp	dword ptr [rbp - 8], 9
jle	0x555555555257
mov	eax, dword ptr [rbp - 8]
cdqe	
lea	rdx, [rax*4 - 1]
mov	rax, qword ptr [rbp - 0x10]
add	rax, rdx
mov	eax, dword ptr [rax]
pxor	xmm0, xmm0
cvtsi2sd	xmm0, eax
movsd	xmm1, qword ptr [rip]
divsd	xmm0, xmm1
cvttsd2si	eax, xmm0
mov	edi, eax
call	0x5555555552a9
push	rbp
mov	rbp, rsp
push	rbx
sub	rsp, 0x28
mov	dword ptr [rbp - 0x24], edi
mov	eax, dword ptr [rbp - 0x24]
cdqe	
shl	rax, 3
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbp - 0x20], rax
lea	rax, [rip + 0x73]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	dword ptr [rbp - 0x14], 0
jmp	0x555555555325
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
mov	edi, 0xa
call	0x555555555040
jmp	qword ptr [rip + 0x2fc2]
push	1
jmp	0x555555555020
push	qword ptr [rip + 0x2fca]
jmp	qword ptr [rip + 0x2fcc]
mov	dword ptr [rbp - 0x18], 0
jmp	0x555555555363
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
push	0
jmp	0x555555555020
push	qword ptr [rip + 0x2fca]
jmp	qword ptr [rip + 0x2fcc]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	eax, dword ptr [rbp - 0x18]
cdqe	
lea	rdx, [rax*8 - 1]
mov	rax, qword ptr [rbp - 0x20]
add	rax, rdx
mov	rax, qword ptr [rax]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
add	dword ptr [rbp - 0x18], 1
mov	eax, dword ptr [rbp - 0x18]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x555555555340
mov	rax, qword ptr [rbp - 0x20]
mov	rdi, rax
call	0x555555555030
jmp	qword ptr [rip + 0x2fca]
nop	
mov	rbx, qword ptr [rbp - 8]
leave	
ret	
add	dword ptr [rbp - 8], 1
cmp	dword ptr [rbp - 8], 9
jle	0x555555555257
mov	eax, dword ptr [rbp - 8]
cdqe	
lea	rdx, [rax*4 - 1]
mov	rax, qword ptr [rbp - 0x10]
add	rax, rdx
mov	eax, dword ptr [rax]
pxor	xmm0, xmm0
cvtsi2sd	xmm0, eax
movsd	xmm1, qword ptr [rip]
divsd	xmm0, xmm1
cvttsd2si	eax, xmm0
mov	edi, eax
call	0x5555555552a9
push	rbp
mov	rbp, rsp
push	rbx
sub	rsp, 0x28
mov	dword ptr [rbp - 0x24], edi
mov	eax, dword ptr [rbp - 0x24]
cdqe	
shl	rax, 3
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbp - 0x20], rax
lea	rax, [rip + 0x73]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	dword ptr [rbp - 0x14], 0
jmp	0x555555555325
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
lea	rax, [rip + 0x56]
mov	rdi, rax
mov	eax, 0
call	0x555555555060
jmp	qword ptr [rip + 0x2fb2]
mov	eax, dword ptr [rbp - 0x24]
cdqe	
mov	edx, dword ptr [rbp - 0x14]
movsxd	rdx, edx
lea	rcx, [rdx*8 - 1]
mov	rdx, qword ptr [rbp - 0x20]
lea	rbx, [rcx + rdx]
mov	rdi, rax
call	0x555555555090
jmp	qword ptr [rip + 0x2f9a]
mov	qword ptr [rbx], rax
add	dword ptr [rbp - 0x14], 1
mov	eax, dword ptr [rbp - 0x14]
cmp	eax, dword ptr [rbp - 0x24]
jl	0x5555555552e7
mov	edi, 0xa
call	0x555555555040
jmp	qword ptr [rip + 0x2fc2]
