#include "elf_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int	main(
		int argc,
		char **argv,
		char **envp
		) {
	(void)(argc);
	(void)(argv);
	(void)(envp);

	if (argc < 2)
		return (EXIT_FAILURE);
	if (elf_manager_load(argv[1]))
		return (EXIT_FAILURE);

	if (elf_manager_move_pht_and_emplace_entries(0))
		return (EXIT_FAILURE);

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
