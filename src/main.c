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
static int				_inject64(t_elf_file *s, size_t first_entry_index, t_ranges *ranges);
static int				_inject32(t_elf_file *s, size_t first_entry_index, t_ranges *ranges);

extern char _binary_resources_stub64_bin_start[];
extern char _binary_resources_stub64_bin_end[];
extern char _binary_resources_stub32_bin_start[];
extern char _binary_resources_stub32_bin_end[];

int	main(int argc, char **argv, char **envp) {
	UNUSED(envp);

	size_t		first_entry_index;
	int			opt;
	t_elf_file	s;
	t_ranges	ranges = list_new();

	set_pn(*argv);
	opterr = 0;
	while ((opt = getopt(argc, argv, "v")) != -1) {
		switch (opt) {
			case 'v':
				set_verbose(true);
				break;
			default:
				break;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		print_usage();
	if (elf_manager_load(&s, *argv))
		return (EXIT_FAILURE);

	first_entry_index = s.hdl.eh.get.phnum(&s) + 1;
	if (elf_manager_move_pht_and_emplace_entries(&s, 3))
		return (EXIT_FAILURE);

	if (s.is_64) {
		if (_inject64(&s, first_entry_index, &ranges))
			return (EXIT_FAILURE);
	} else {
		if (_inject32(&s, first_entry_index, &ranges))
			return (EXIT_FAILURE);
	}
	for (size_t k = 0; k < ranges.len - 1 && ranges.len != 0; ++k) {
		auto const	start_off = ALIGN_UP(ranges.data[k].off + ranges.data[k].len - 1, 8);
		auto const	size = MIN(((off_t)ALIGN_DOWN(ranges.data[k + 1].off, 8)) - (off_t)start_off, (off_t)(s.size - start_off));
		verbose("0x%llx => 0x%llx\n", start_off, start_off + size - 1);
		if (size <= 0)
			continue;
		xtea_encrypt((char *)s.data + start_off, size, (const uint32_t *)"1234567812345678");
	}
	if (elf_manager_finalize(&s, "woody"))
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}

static int	_inject64(t_elf_file *s, size_t first_entry_index, t_ranges *ranges) {
	t_ranges	bss_ranges = list_new();
	verbose("getting protected ranges...");
	if (!elf_get_protected_ranges(s, ranges))
		return (1);
	verbose("%zu found !\n", ranges->len);
	verbose("getting bss ranges...");
	if (!elf_get_bss_vaddr_ranges(s, &bss_ranges))
		return (1);
	verbose("%zu found !\n", bss_ranges.len);


	verbose("append stub64...");
	elf_append_loadable_data_and_locate(
		s,
		_binary_resources_stub64_bin_start,
		_binary_resources_stub64_bin_end - _binary_resources_stub64_bin_start,
		0x1000, 0x20, first_entry_index,
		PF_X | PF_R | PF_W
	);
	verbose("done !\n");
	list_push(ranges, MAKE_RANGE(s->hdl.ph.get.offset(s, first_entry_index), s->hdl.ph.get.filesz(s, first_entry_index)));
	range_aggregate(ranges);

	verbose("append protected ranges...");
	elf_append_loadable_data_and_locate(
		s,
		ranges->data,
		(ranges->len + 2) * sizeof(*ranges->data),
		0x1000, 0x20, first_entry_index + 1,
		PF_R
	);
	verbose("done !\n");

	verbose("append bss ranges...");
	elf_append_loadable_data_and_locate(
		s,
		bss_ranges.data,
		bss_ranges.len * sizeof(*bss_ranges.data),
		0x1000, 0x20, first_entry_index + 2,
		PF_R
	);
	verbose("done !\n");

	verbose("editing last_ranges...");
	t_range *last_ranges = s->data + s->hdl.ph.get.offset(s, first_entry_index + 1) + s->hdl.ph.get.memsz(s, first_entry_index + 1) - sizeof(t_range) * 2;
	last_ranges[0].off = s->hdl.ph.get.offset(s, first_entry_index + 1);
	last_ranges[0].len = (ranges->len + 2) * sizeof(t_range);
	last_ranges[1].off = s->hdl.ph.get.offset(s, first_entry_index + 2);
	last_ranges[1].len = bss_ranges.len * sizeof(t_range);
	verbose("done !\n");

	verbose("editing stub_data...");
	t_stub_64_data *stub_data = s->data + s->hdl.ph.get.offset(s, first_entry_index) + s->hdl.ph.get.memsz(s, first_entry_index) - sizeof(t_stub_64_data);
	stub_data->stub_virt_off = s->hdl.ph.get.vaddr(s, first_entry_index);
	stub_data->entry_point = s->hdl.eh.get.entry(s);
	stub_data->ranges_ptr = (uint64_t)s->hdl.ph.get.vaddr(s, first_entry_index + 1);
	stub_data->ranges_len = ranges->len + 2;
	stub_data->bss_ranges_ptr = (uint64_t)s->hdl.ph.get.vaddr(s, first_entry_index + 2);
	stub_data->bss_ranges_len = bss_ranges.len;
	verbose("done !\n");

	s->hdl.eh.set.entry(s, s->hdl.ph.get.vaddr(s, first_entry_index));
	verbose("stub is off: 0x%llx, len: 0x%llx\n", s->hdl.ph.get.offset(s, first_entry_index), s->hdl.ph.get.filesz(s, first_entry_index));
	return (0);
}

static int	_inject32(t_elf_file *s, size_t first_entry_index, t_ranges *ranges) {
	t_ranges	bss_ranges = list_new();
	if (!elf_get_protected_ranges(s, ranges))
		return (1);
	if (!elf_get_bss_vaddr_ranges(s, &bss_ranges))
		return (1);

	elf_append_loadable_data_and_locate(
		s,
		_binary_resources_stub32_bin_start,
		_binary_resources_stub32_bin_end - _binary_resources_stub32_bin_start,
		0x1000, 0x20, first_entry_index,
		PF_X | PF_R | PF_W
	);
	list_push(ranges, MAKE_RANGE(s->hdl.ph.get.offset(s, first_entry_index), s->hdl.ph.get.filesz(s, first_entry_index)));
	range_aggregate(ranges);

	elf_append_loadable_data_and_locate(
		s,
		ranges->data,
		(ranges->len + 2) * sizeof(*ranges->data),
		0x1000, 0x20, first_entry_index + 1,
		PF_R
	);

	elf_append_loadable_data_and_locate(
		s,
		bss_ranges.data,
		bss_ranges.len * sizeof(*bss_ranges.data),
		0x1000, 0x20, first_entry_index + 2,
		PF_R
	);

	t_range *last_ranges = s->data + s->hdl.ph.get.offset(s, first_entry_index + 1) + s->hdl.ph.get.memsz(s, first_entry_index + 1) - sizeof(t_range) * 2;
	last_ranges[0].off = s->hdl.ph.get.offset(s, first_entry_index + 1);
	last_ranges[0].len = (ranges->len + 2) * sizeof(t_range);
	last_ranges[1].off = s->hdl.ph.get.offset(s, first_entry_index + 2);
	last_ranges[1].len = bss_ranges.len * sizeof(t_range);

	t_stub_32_data *stub_data = s->data + s->hdl.ph.get.offset(s, first_entry_index) + s->hdl.ph.get.memsz(s, first_entry_index) - sizeof(t_stub_32_data);
	stub_data->stub_virt_off = s->hdl.ph.get.vaddr(s, first_entry_index);
	stub_data->entry_point = s->hdl.eh.get.entry(s);
	stub_data->ranges_ptr = s->hdl.ph.get.vaddr(s, first_entry_index + 1);
	stub_data->ranges_len = ranges->len + 2;
	stub_data->bss_ranges_ptr = s->hdl.ph.get.vaddr(s, first_entry_index + 2);
	stub_data->bss_ranges_len = bss_ranges.len;

	s->hdl.eh.set.entry(s, s->hdl.ph.get.vaddr(s, first_entry_index));
	return (0);
}

static noreturn void	print_usage() {
	printf("Usage: woody_woodpacker EXEC\n");
	exit(EXIT_FAILURE);
}
