#include <stdlib.h>
#include <stdnoreturn.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include "elf_reader.h"
#include "utils.h"

static noreturn void	print_usage();

int	main(
		int argc,
		char **argv,
		char **envp
		) {
	int	opt;
	UNUSED(argc);
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

	if (elf_manager_move_pht_and_emplace_entries(0))
		return (EXIT_FAILURE);

	if (elf_manager_finalize())
		return (EXIT_FAILURE);

	return (EXIT_SUCCESS);
}

static noreturn void   print_usage() {
	printf("Usage: woody_woodpacker EXEC\n");
	exit(EXIT_FAILURE);
}
