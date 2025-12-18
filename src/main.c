#include <stdlib.h>
#include <stdnoreturn.h>
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
	UNUSED(envp);
	size_t	first_entry_index;
	int		opt;

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

	return (EXIT_SUCCESS);
}

static noreturn void   print_usage() {
	printf("Usage: woody_woodpacker EXEC\n");
	exit(EXIT_FAILURE);
}
