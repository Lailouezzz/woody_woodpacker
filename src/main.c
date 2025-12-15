#include <getopt.h>
#include <stdlib.h>
#include "utils.h"

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
	perror_msg("perror_msg");
	error_msg("error_msg");
	verbose("verbose");
	return (EXIT_SUCCESS);
}
