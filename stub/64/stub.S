.intel_syntax noprefix

.global _start
.extern stub_main
.extern stub_begin

.section .stub.init

_start:
	push rdx
	push rbp
	call stub_main

	push rax
	mov rax, 1
	mov rdi, 1
	lea rsi, [rip + msg]
	mov rdx, 12
	syscall

	pop rax
	pop rbp
	pop rdx
	jmp rax

.section .rodata
msg:
	.ascii "___WOODY___\n"
