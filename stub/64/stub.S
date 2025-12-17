.intel_syntax noprefix

.global _start
.extern stub_main
.extern stub_begin

.section .stub_init

_start:

	push rdx
	push rbp
	lea rax, [rip + stub_begin]
	mov r11, 0x4242424242424242
	sub rax, r11
	mov r11, 0x4141414141414141
	add rax, r11
	push rax
	call stub_main

	mov rax, 1
	mov rdi, 1
	lea rsi, [rip + msg]
	mov rdx, 14
	syscall

	pop rax
	pop rbp
	pop rdx
	jmp rax

.section .rodata
msg:
	.ascii "___WOODY___\n"
