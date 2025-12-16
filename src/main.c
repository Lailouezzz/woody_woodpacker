#include <stdlib.h>
#include <stdnoreturn.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/stat.h>
#include "utils.h"

TYPEDEF_LIST(Elf64_Phdr, Elf64_Phdr_list);

static Elf64_Addr	find_last_vaddr(
						const Elf64_Phdr_list_t *pht
						);

static noreturn void	print_usage();

int	main(
		int argc,
		char **argv
		) {
	int	opt;

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
	bytes_t	data = list_new();
	bytes_t	data2 = list_new();
	int fd = open(*argv, O_RDONLY);
	struct stat st;
	if (fstat(fd, &st) != 0) {
		perror_msg("fstat()");
		return (EXIT_FAILURE);
	}
	if (!list_reserve(&data, st.st_size)) {
		error_msg("list_reserve");
		return (EXIT_FAILURE);
	}
	data.len = read(fd, data.data, st.st_size);
	close(fd);
	Elf64_Ehdr	*ehdr = (void*)data.data;
	if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0) {
		error_msg("Invalid elf magic");
		return (EXIT_FAILURE);
	}
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		error_msg("Invalid elf class");
		return (EXIT_FAILURE);
	}
	list_push_range(&data2, data.data, data.len);
	list_reserve(&data2, (data.len + 0x8 - 1) & (~(0x8UL - 1UL))); // align EOF to 0x8
	ehdr = (void*)data2.data;
	Elf64_Phdr_list_t pht = list_new();
	list_push_range(&pht, (Elf64_Phdr *)(data.data + ehdr->e_phoff), ehdr->e_phnum);
	Elf64_Addr pht_vaddr = find_last_vaddr(&pht) + 1;
	pht_vaddr = (pht_vaddr + 0x1000 - 1) & (~(0x1000UL - 1UL));
	pht_vaddr += data2.len % 0x1000;
	Elf64_Phdr newphdr = {
		.p_align = 0x1000,
		.p_filesz = (pht.len + 1) * sizeof(*pht.data),
		.p_flags = PF_R,
		.p_memsz = (pht.len + 1) * sizeof(*pht.data),
		.p_offset = data2.len,
		.p_paddr = pht_vaddr,
		.p_type = PT_LOAD,
		.p_vaddr = pht_vaddr,
	};
	list_push(&pht, newphdr);
	pht.data[0].p_vaddr = pht_vaddr;
	pht.data[0].p_paddr = pht_vaddr;
	pht.data[0].p_offset = data2.len;
	pht.data[0].p_filesz = pht.len * sizeof(*pht.data);
	pht.data[0].p_memsz = pht.len * sizeof(*pht.data);
	verbose("PHT SIZE : %zu\n", pht.len);
	verbose("PHT OFF : %zu\n", data2.len);
	ehdr->e_phnum = pht.len;
	ehdr->e_phoff = data2.len;
	list_push_range(&data2, (char *)pht.data, pht.len * sizeof(*pht.data));
	fd = open("woody", O_CREAT | O_RDWR, 0755);
	write(fd, data2.data, data2.len);
	close(fd);
	list_free(&data);
	list_free(&data2);
	list_free(&pht);
	return (EXIT_SUCCESS);
}

static Elf64_Addr	find_last_vaddr(const Elf64_Phdr_list_t *pht) {
	Elf64_Addr last = 0;
	Elf64_Phdr *it;
	list_foreach(pht, it) {
		Elf64_Addr end = it->p_vaddr + it->p_memsz;
		if (end > last)
			last = end;
	}
	return last;
}

static noreturn void	print_usage() {
	printf("Usage: woody_woodpacker EXEC\n");
	exit(EXIT_FAILURE);
}
