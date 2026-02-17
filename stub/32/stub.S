.intel_syntax noprefix

.global _start
.extern stub_main
.extern stub_begin

.section .stub.init

_start:
	and esp, ~0xf
	push 0 # ret placeholder
	pushad
	pushfd

	sub esp, 8
	call stub_main
	add esp, 8
	mov [esp + 36], eax

	call .L_get_pc1
.L_get_pc1:
	pop ecx
	add ecx, (msg - .L_get_pc1)
	mov eax, 4 # SYS_WRITE
	mov ebx, 1 # fd stdout
	mov edx, 12 # size
	int 0x80

	popfd
	popad
	ret

.section .data
entry_point:
	.long 0

.section .rodata
msg:
	.ascii "___WOODY___\n"
