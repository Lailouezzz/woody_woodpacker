#include <stdlib.h>
#include <stdnoreturn.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include "elf_reader.h"
#include "protect_range.h"
#include "utils.h"
#include "encrypt.h"
#include "stub/32/stub_def.h"
#include "stub/64/stub_def.h"

static noreturn void	print_usage();

extern char _binary_ressources_stub64_bin_start[];
extern char _binary_ressources_stub64_bin_end[];
extern char _binary_ressources_stub32_bin_start[];
extern char _binary_ressources_stub32_bin_end[];

int	main(
		int argc,
		char **argv,
		char **envp
		) {
	UNUSED(envp);

	size_t		first_entry_index;
	int			opt;
	t_elf_file	s;

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
	if (elf_manager_load(&s, *argv))
		return (EXIT_FAILURE);

	first_entry_index = s.hdl.eh.get.phnum(&s) + 1;
	if (elf_manager_move_pht_and_emplace_entries(&s, 2))
		return (EXIT_FAILURE);

	t_ranges	ranges = list_new();

	if (s.is_64) {
		if (!elf_get_protected_ranges(&s, &ranges)) {
			return (EXIT_FAILURE);
		}
		elf_append_loadable_data_and_locate(
			&s,
			_binary_ressources_stub64_bin_start,
			_binary_ressources_stub64_bin_end - _binary_ressources_stub64_bin_start,
			0x1000,
			0x20,
			first_entry_index,
			PF_X | PF_R | PF_W
		);
		list_push(&ranges, MAKE_RANGE(s.hdl.ph.get.offset(&s, first_entry_index), s.hdl.ph.get.filesz(&s, first_entry_index)));
		range_aggregate(&ranges);
		elf_append_loadable_data_and_locate(
			&s,
			ranges.data,
			(ranges.len + 1) * sizeof(*ranges.data),
			0x1000,
			0x20,
			first_entry_index + 1,
			PF_R
		);
		list_push(&ranges, MAKE_RANGE(s.hdl.ph.get.offset(&s, first_entry_index+1), s.hdl.ph.get.filesz(&s, first_entry_index+1)));
		range_aggregate(&ranges);
		list_foreach(&ranges, it) {
			verbose("PROTECTED RANGE :\nOFF : 0x%lx\nLEN : 0x%zx\n", it->off, it->len);
		}
		t_range *last_range = s.data + s.hdl.ph.get.offset(&s, first_entry_index + 1) + s.hdl.ph.get.memsz(&s, first_entry_index + 1) - sizeof(t_range);

		last_range->off = s.hdl.ph.get.offset(&s, first_entry_index + 1);
		last_range->len = (ranges.len + 1) * sizeof(t_range);


		t_stub_64_data	*stub_data = s.data + s.hdl.ph.get.offset(&s, first_entry_index) + s.hdl.ph.get.memsz(&s, first_entry_index) - sizeof(t_stub_64_data);
		stub_data->stub_virt_off = s.hdl.ph.get.vaddr(&s, first_entry_index);
		stub_data->entry_point = s.hdl.eh.get.entry(&s);
		stub_data->ranges.data = (void*)(uintptr_t)s.hdl.ph.get.vaddr(&s, first_entry_index + 1);
		stub_data->ranges.len = ranges.len + 1;
		s.hdl.eh.set.entry(&s, s.hdl.ph.get.vaddr(&s, first_entry_index));
		verbose("stub is off: 0x%lx, len: 0x%zx\n", s.hdl.ph.get.offset(&s, first_entry_index), s.hdl.ph.get.filesz(&s, first_entry_index));
	} else {
		elf_append_loadable_data_and_locate(
			&s,
			_binary_ressources_stub32_bin_start,
			_binary_ressources_stub32_bin_end - _binary_ressources_stub32_bin_start,
			0x1000,
			0x20,
			first_entry_index,
			PF_X | PF_R | PF_W
		);

		t_stub_32_data	*stub_data = s.data + s.hdl.ph.get.offset(&s, first_entry_index) + s.hdl.ph.get.memsz(&s, first_entry_index) - sizeof(t_stub_32_data);
		stub_data->stub_virt_off = s.hdl.ph.get.vaddr(&s, first_entry_index);
		stub_data->entry_point = s.hdl.eh.get.entry(&s);
		s.hdl.eh.set.entry(&s, s.hdl.ph.get.vaddr(&s, first_entry_index));
	}

	for (size_t k = 0; k < ranges.len - 1 && ranges.len != 0; ++k) {
		auto const	start_off = ALIGN_UP(ranges.data[k].off + ranges.data[k].len, 8);
		auto const	size = ((off_t)ALIGN_DOWN(ranges.data[k + 1].off, 8)) - (off_t)start_off;
		if (size <= 0)
			continue ;
		verbose("ENCRYPT FROM : 0x%lx TO : 0x%lx (size: 0x%lx)\n", start_off, start_off + size - 1, size);
		xtea_encrypt((char *)s.data + start_off, size, (const uint32_t *)"1234567812345678");
	}
	if (elf_manager_finalize(&s, "woody"))
		return (EXIT_FAILURE);

	return (EXIT_SUCCESS);
}

static noreturn void   print_usage() {
	printf("Usage: woody_woodpacker EXEC\n");
	exit(EXIT_FAILURE);
}
