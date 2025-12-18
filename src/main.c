#include "elf_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include "elf_reader.h"
#include "utils.h"
#include "stub/64/stub_def.h"

static noreturn void	print_usage();

extern char _binary_ressources_stub64_bin_start[];
extern char _binary_ressources_stub64_bin_end[];

int	main(
		int argc,
		char **argv,
		char **envp
		) {
	size_t	first_entry_index;
	int		opt;
	UNUSED(envp);

	set_pn(*argv);
	opterr = 0;
	while ((opt = getopt(argc, argv, "v")) != -1) {
		switch (opt) {
			case 'v':
				set_verbose(true);
			break;
			default:
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1) {
		print_usage();
	}
	if (argc != 1)
		print_usage();
	if (elf_manager_load(*argv))
		return (EXIT_FAILURE);

	first_entry_index = elf_eh_get_phnum() + 1;
	if (elf_manager_move_pht_and_emplace_entries(1))
		return (EXIT_FAILURE);

	uint64_t stub_vaddr = ALIGN_ON(elf_get_next_vaddr() + 1, 0x1000);
	stub_vaddr += elf_get_size() % 0x1000;

	stub_64_data_t	*stub_data = (void*)((uintptr_t)_binary_ressources_stub64_bin_end - sizeof(stub_64_data_t));
	stub_data->stub_virt_off = stub_vaddr;
	verbose("virt off 0x%llx\n", stub_data->stub_virt_off);
	stub_data->entry_point = elf_eh_get_entry();
	verbose("entry 0x%llx\n", stub_data->entry_point);

	elf_eh_set_entry(stub_vaddr);

	elf_append_loadable_data_and_locate(
		_binary_ressources_stub64_bin_start,
		_binary_ressources_stub64_bin_end - _binary_ressources_stub64_bin_start,
		0x1000,
		first_entry_index,
		PF_X | PF_R | PF_W
	);

	UNUSED(first_entry_index);

	if (elf_manager_finalize())
		return (EXIT_FAILURE);

// 	size_t	phtsize = (size_t)elf_eh_get_phnum() * (size_t)elf_eh_get_phentsize();
// //	size_t	phtnum = s.er.ph.get_num(&s);
// //	size_t	phentsize = s.er.ph.get_num(&s);
// 	void	*pht = elf_eh_get_pht();

// //	size_t	section_size = (phtnum * phtsize + 0x8 - 1) & (~(0x8UL - 1UL));

// 	elf_eh_set_phoff(elf_get_size());

	// int		fd = open("out", O_WRONLY | O_CREAT, 0777);
	// size_t	written = 0;
	// while (written < elf_get_size())
	// {
	// 	ssize_t n = write(fd, &((uint8_t *)elf_get_raw_data())[written], elf_get_size() - written);
	// 	if (n < 0)
	// 	{
	// 		close(fd);
	// 		unlink("out");
	// 		return (EXIT_FAILURE);
	// 	}
	// 	written += n;
	// }

// 	written = 0;
// 	while (written < phtsize)
// 	{
// 		ssize_t n = write(fd, &((uint8_t *)pht)[written], phtsize - written);
// 		if (n < 0)
// 		{
// 			close(fd);
// 			unlink("out");
// 			return (EXIT_FAILURE);
// 		}
// 		written += n;
// 	}

//	Elf64_Phdr	n = (Elf64_Phdr){
//		.p_align = 0x1000,
//		.p_filesz = s.er.ph.get_num(&s) * s.er.ph.get_entsize(&s),
//		.p_flags = PF_R,
//		.p_memsz = s.er.ph.get_num(&s) * s.er.ph.get_entsize(&s),
//		.p_offset = section_size,
//	};

	return (EXIT_SUCCESS);
}

/*
static
Elf64_Addr	_find_last_vaddr(
				t_elf_file *s
				)
{
	size_t		n = s->er.ph.get_num(s);
	Elf64_Phdr	*phd_ptr = s->er.ph.get_header(s);
	Elf64_Addr	last = 0;

	while (n--)
	{
		uint64_t	base = phd_ptr->p_vaddr;
		uint64_t	size = phd_ptr->p_memsz;
		uint64_t	end = base + size;

		if (end > last)
			last = end;
		++phd_ptr;
	}
	return (last);
}
*/
