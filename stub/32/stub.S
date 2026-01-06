.intel_syntax noprefix

.global _start
.extern stub_main
.extern stub_begin

.section .stub.init

_start:
	# Sauvegarder les registres importants
	push edx
	push ebp

	# Appeler stub_main (convention cdecl : retourne dans eax)
	call stub_main

	# Sauvegarder le point d'entrée retourné
	push eax

	# Afficher "___WOODY___\n" avec syscall write (32 bits)
	# sys_write = 4, stdout = 1
	# eax = syscall number, ebx = fd, ecx = buf, edx = count

	# Obtenir l'adresse de msg en PIC (trick call/pop)
	call .get_pc
.get_pc:
	pop ecx                    # ecx = adresse de cette instruction
	add ecx, (msg - .get_pc)   # ecx = adresse de msg

	mov eax, 4                 # sys_write
	mov ebx, 1                 # stdout
	# ecx contient déjà l'adresse de msg
	mov edx, 12                # taille
	int 0x80                   # syscall 32 bits

	# Restaurer et sauter au point d'entrée original
	pop eax
	pop ebp
	pop edx
	jmp eax

.section .rodata
msg:
	.ascii "___WOODY___\n"
