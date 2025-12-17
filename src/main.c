#include <stdlib.h>
#include <stdnoreturn.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/stat.h>
#include "stub/64/stub_def.h"
#include "utils.h"

TYPEDEF_LIST(Elf64_Phdr, Elf64_Phdr_list);

extern char _binary_ressources_stub64_bin_start[];
extern char _binary_ressources_stub64_bin_end[];

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
	bytes_t	orig_data = list_new();
	bytes_t	woody_data = list_new();
	int fd = open(*argv, O_RDONLY);
	struct stat st;
	if (fstat(fd, &st) != 0) {
		perror_msg("fstat()");
		return (EXIT_FAILURE);
	}
	if (!list_reserve(&orig_data, st.st_size)) {
		error_msg("list_reserve");
		return (EXIT_FAILURE);
	}
	orig_data.len = read(fd, orig_data.data, st.st_size);
	close(fd);
	Elf64_Ehdr	*ehdr = (void*)orig_data.data;
	if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0) {
		error_msg("Invalid elf magic");
		return (EXIT_FAILURE);
	}
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		error_msg("Invalid elf class");
		return (EXIT_FAILURE);
	}
	list_push_range(&woody_data, orig_data.data, orig_data.len);
	Elf64_Phdr_list_t pht = list_new(); // Local copy of pht
	list_push_range(&pht, (Elf64_Phdr *)(orig_data.data + ehdr->e_phoff), ehdr->e_phnum);

	Elf64_Addr text_vaddr = find_last_vaddr(&pht) + 1;
	text_vaddr = (text_vaddr + 0x1000 - 1) & (~(0x1000UL - 1UL));
	text_vaddr += woody_data.len % 0x1000;

	// Insert stub
	stub_64_data_t	*stub_data = (void*)((uintptr_t)_binary_ressources_stub64_bin_end - sizeof(stub_64_data_t));
	stub_data->stub_virt_off = text_vaddr;
	verbose("virt off 0x%llx\n", stub_data->stub_virt_off);
	stub_data->entry_point = ehdr->e_entry;
	verbose("entry 0x%llx\n", stub_data->entry_point);

	Elf64_Phdr newtext = {
		.p_align = 0x1000,
		.p_filesz = _binary_ressources_stub64_bin_end - _binary_ressources_stub64_bin_start,
		.p_flags = PF_X | PF_R | PF_W,
		.p_memsz = _binary_ressources_stub64_bin_end - _binary_ressources_stub64_bin_start,
		.p_offset = woody_data.len,
		.p_paddr = text_vaddr,
		.p_type = PT_LOAD,
		.p_vaddr = text_vaddr,
	};
	list_push(&pht, newtext);
	ehdr = (void*)woody_data.data;
	ehdr->e_entry = text_vaddr;

	list_push_range(&woody_data, _binary_ressources_stub64_bin_start, _binary_ressources_stub64_bin_end - _binary_ressources_stub64_bin_start);
	list_reserve(&woody_data, (woody_data.len + 0x8 - 1) & (~(0x8UL - 1UL))); // align EOF to 0x8 ; valgrind say unused value passed to write beceause of this
	Elf64_Addr pht_vaddr = find_last_vaddr(&pht) + 1;
	pht_vaddr = (pht_vaddr + 0x1000 - 1) & (~(0x1000UL - 1UL));
	pht_vaddr += woody_data.len % 0x1000;
	Elf64_Phdr newphdr = {
		.p_align = 0x1000,
		.p_filesz = (pht.len + 1) * sizeof(*pht.data),
		.p_flags = PF_R,
		.p_memsz = (pht.len + 1) * sizeof(*pht.data),
		.p_offset = woody_data.len,
		.p_paddr = pht_vaddr,
		.p_type = PT_LOAD,
		.p_vaddr = pht_vaddr,
	};
	list_push(&pht, newphdr);
	pht.data[0].p_vaddr = pht_vaddr;
	pht.data[0].p_paddr = pht_vaddr;
	pht.data[0].p_offset = woody_data.len;
	pht.data[0].p_filesz = pht.len * sizeof(*pht.data);
	pht.data[0].p_memsz = pht.len * sizeof(*pht.data);
	verbose("PHT SIZE : %zu\n", pht.len);
	verbose("PHT OFF : %zu\n", woody_data.len);
	ehdr = (void*)woody_data.data;
	ehdr->e_phnum = pht.len;
	ehdr->e_phoff = woody_data.len;
	list_push_range(&woody_data, (char *)pht.data, pht.len * sizeof(*pht.data));
	fd = open("woody", O_CREAT | O_RDWR, 0755);
	write(fd, woody_data.data, woody_data.len);
	close(fd);
	list_free(&orig_data);
	list_free(&woody_data);
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
