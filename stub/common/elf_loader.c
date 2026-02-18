// ---
// Includes
// ---

#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "elf_reader.h"
#include "utils.h"

// ---
// Static function declarations
// ---



// ---
// Extern function definitions
// ---

void	*elf_load(const char *path) {
	t_elf_file	s;
	uintptr_t	min_vaddr;
	uintptr_t	max_vaddr;
	void		*base;
	uint16_t	phnum;

	if (elf_manager_load(&s, path) == EXIT_FAILURE)
		return (nullptr);
	phnum = s.hdl.eh.get.phnum(&s);
	for (size_t k = 0; k < phnum; ++k) {
		if (s.hdl.ph.get.type(&s, k) != PT_LOAD)
			continue ;
		auto const	start_vaddr = s.hdl.ph.get.vaddr(&s, k);
		auto const	last_vaddr = start_vaddr + s.hdl.ph.get.memsz(&s, k) - 1;
		if (min_vaddr > start_vaddr)
			min_vaddr = start_vaddr;
		if (max_vaddr < last_vaddr)
			max_vaddr = last_vaddr;
	}
	base = mmap(NULL, ALIGN_UP(max_vaddr - min_vaddr, 0x1000), PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (base == MAP_FAILED) {
		elf_manager_close(&s);
		return (nullptr);
	}
	for (size_t k = 0; k < phnum; ++k) {
		if (s.hdl.ph.get.type(&s, k) != PT_LOAD)
			continue ;
		auto const	vaddr = s.hdl.ph.get.vaddr(&s, k);
		auto const	memsz = s.hdl.ph.get.memsz(&s, k);
		auto const	filesz = s.hdl.ph.get.filesz(&s, k);
		auto const	poff = s.hdl.ph.get.offset(&s, k);
		auto const	flags = s.hdl.ph.get.flags(&s, k);
		int const	prot = ((flags & PF_R) ? PROT_READ : 0)
						| ((flags & PF_W) ? PROT_WRITE : 0)
						| ((flags & PF_X) ? PROT_EXEC : 0);
	}
}

// ---
// Static function definitions
// ---
