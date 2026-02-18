/**
 * @file stub.c
 * @brief 64-bit stub entry point and decryption orchestration.
 */

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "stub.h"

__attribute__((section(".stub.data")))
t_stub_64_data	g_stub_data = {.entry_point = 0x4242, .stub_virt_off = 0x4242};

extern char	stub_begin[];
extern char	stub_end[];
static char	*_base;

// ---
// Static functions declarations
// ---

static const char	*_restore_interp(
						Elf64_Phdr *phdr,
						int interp_idx
						);

static Elf64_auxv_t	*_auxv_from_stack(
						uintptr_t *stack
						);

static Elf64_Phdr	*_phdr_from_auxv(
						const Elf64_auxv_t *auxv
						);

// ---
// Stub entry
// ---

/**
 * @brief Stub main function called from assembly entry.
 * @return Pointer to original entry point.
 */
void *stub_main(void *stack)
{
	Elf64_auxv_t	*auxv;
	Elf64_Phdr		*phdr;
	const char		*interp_path;

	_base = (char *)stub_begin - g_stub_data.stub_virt_off;
	g_stub_data.ranges_ptr = (uintptr_t)(g_stub_data.ranges_ptr + _base);
	g_stub_data.bss_ranges_ptr = (uintptr_t)(g_stub_data.bss_ranges_ptr + _base);
	decrypt((uint64_t)_base,
		(t_range *)g_stub_data.ranges_ptr, g_stub_data.ranges_len,
		(t_range *)g_stub_data.bss_ranges_ptr, g_stub_data.bss_ranges_len);
	auxv = _auxv_from_stack(stack);
	phdr = _phdr_from_auxv(auxv);
	interp_path = (const char *)_restore_interp(phdr, g_stub_data.interp_idx);
	if (interp_path != nullptr) {
		write(STDOUT_FILENO, interp_path, strlen(interp_path));
	}

	return (g_stub_data.entry_point + _base);
}

// ---
// Static functions definitions
// ---

static const char	*_restore_interp(
						Elf64_Phdr *phdr,
						int interp_idx
						) {
	if (interp_idx == -1)
		return (nullptr);

	void	*page_start = (void *)ALIGN_DOWN((uintptr_t)&phdr[interp_idx], 0x1000);
	size_t	page_len = ALIGN_UP((uintptr_t)&phdr[interp_idx + 1], 0x1000) - (uintptr_t)page_start;
	mprotect(page_start, page_len, PROT_READ | PROT_WRITE);
	phdr[interp_idx].p_type = PT_INTERP;
	mprotect(page_start, page_len, PROT_READ);
	return (phdr[interp_idx].p_vaddr + _base);
}

static Elf64_auxv_t	*_auxv_from_stack(
						uintptr_t *stack
						) {
	uintptr_t	argc;

	argc = *stack++;
	stack += argc + 1;
	while ((void*)*stack++ != nullptr) ;
	return (Elf64_auxv_t *)(stack);
}

static Elf64_Phdr	*_phdr_from_auxv(
						const Elf64_auxv_t *auxv
						) {
	while (auxv->a_type != AT_NULL) {
		switch (auxv->a_type) {
			case AT_PHDR:
				return ((Elf64_Phdr *)auxv->a_un.a_val);
		}
		++auxv;
	}
	return (NULL);
}
