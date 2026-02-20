#include <stdlib.h>
#include <stdnoreturn.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/random.h>
#include "elf_reader.h"
#include "protect_range.h"
#include "utils.h"
#include "encrypt.h"
#include "stub/32/stub_def.h"
#include "stub/64/stub_def.h"

#define KEY_SIZE (16)

static noreturn void	print_usage();
static void				_append_segment(t_elf_file *s, size_t pht_idx, void *data, size_t size, uint32_t flags);
static void				_populate_stub_data(t_elf_file *s, size_t first_entry_index, int interp_idx, const char *key);
static int				_inject(t_elf_file *s, size_t first_entry_index, t_ranges *ranges, int interp_idx, const char *key);
static void				_encrypt(t_elf_file *s, t_ranges *ranges, const char *key);
static char				*_key_from_str(const char *key);

extern char _binary_resources_stub64_bin_start[];
extern char _binary_resources_stub64_bin_end[];
extern char _binary_resources_stub32_bin_start[];
extern char _binary_resources_stub32_bin_end[];

typedef enum {
	PHT_IDX_STUB,
	PHT_IDX_BSS_RANGES,
	PHT_IDX_PROTECTED_RANGES,
	PHT_IDX__NB,
}	e_pht_idx;

int	main(int argc, char **argv, char **envp) {
	UNUSED(envp);

	size_t		first_entry_index;
	int			opt;
	int			interp_idx;
	t_elf_file	s;
	t_ranges	ranges = list_new();
	char		*key;
	bool		user_key;

	set_pn(*argv);
	user_key = false;
	key = nullptr;
	opterr = 0;
	while ((opt = getopt(argc, argv, "vk::")) != -1) {
		switch (opt) {
			case 'v':
				set_verbose(true);
				break ;
			case 'k':
				if (optarg) {
					key = _key_from_str(optarg);
				} else if (optind < argc && argv[optind][0] != '-') {
					key = _key_from_str(argv[optind++]);
				} else {
					key = nullptr;
				}
				user_key = true;
				break ;
		break;
			default:
				break ;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1 || (user_key && key == nullptr))
		print_usage();
	if (elf_manager_load(&s, *argv)) {
		list_free(&ranges);
		return (EXIT_FAILURE);
	}

	if (key == nullptr) {
		key = malloc(KEY_SIZE);
		getrandom(key, KEY_SIZE, 0);
	}

	printf("Key: 0x");
	for (size_t k = 0; k < KEY_SIZE; ++k) {
		printf("%hhx", key[k]);
	}
	printf("\n");

	first_entry_index = s.hdl.eh.get.phnum(&s) + 1;
	if (elf_manager_move_pht_and_emplace_entries(&s, 3)) {
		list_free(&ranges);
		free(key);
		return (EXIT_FAILURE);
	}

	interp_idx = elf_find_ph_index(&s, elf_ph_is_interp);

	if (interp_idx != -1) {
		s.hdl.ph.set.type(&s, interp_idx, PT_NULL);
	}

	if (_inject(&s, first_entry_index, &ranges, interp_idx, key)) {
		list_free(&ranges);
		free(key);
		return (EXIT_FAILURE);
	}
	verbose("protected ranges:\n");
	int k = 0;
	list_foreach(&ranges, it) {
		verbose("  [%d] %llx -> %llx\n", k++, it->off, it->off + it->len - 1);
	}
	_encrypt(&s, &ranges, key);
	free(key);
	list_free(&ranges);
	if (elf_manager_finalize(&s, "woody"))
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}

static void	_append_segment(
				t_elf_file *s,
				size_t pht_idx,
				void *data,
				size_t size,
				uint32_t flags) {
	elf_append_loadable_data_and_locate(s, data, size, 0x1000, 0x20, pht_idx, flags);
}

static void	_populate_stub_data(
				t_elf_file *s,
				size_t first_entry_index,
				int interp_idx,
				const char *key) {
	size_t		stub_idx = first_entry_index + PHT_IDX_STUB;
	size_t		bss_idx = first_entry_index + PHT_IDX_BSS_RANGES;
	size_t		prot_idx = first_entry_index + PHT_IDX_PROTECTED_RANGES;
	size_t		stub_data_size = s->is_64 ? sizeof(t_stub_64_data) : sizeof(t_stub_32_data);

	t_range *last_ranges = s->data + s->hdl.ph.get.offset(s, prot_idx) + s->hdl.ph.get.memsz(s, prot_idx) - sizeof(t_range);
	*last_ranges = MAKE_RANGE(s->hdl.ph.get.offset(s, first_entry_index), SIZE_MAX);

	void *stub_data = s->data
		+ s->hdl.ph.get.offset(s, stub_idx)
		+ s->hdl.ph.get.memsz(s, stub_idx)
		- stub_data_size;

	if (s->is_64) {
		t_stub_64_data *d = stub_data;
		d->stub_virt_off = s->hdl.ph.get.vaddr(s, stub_idx);
		d->entry_point = s->hdl.eh.get.entry(s);
		d->ranges_ptr = s->hdl.ph.get.vaddr(s, prot_idx);
		d->ranges_len = s->hdl.ph.get.filesz(s, prot_idx) / sizeof(t_range);
		d->bss_ranges_ptr = s->hdl.ph.get.vaddr(s, bss_idx);
		d->bss_ranges_len = s->hdl.ph.get.filesz(s, bss_idx) / sizeof(t_range);
		d->interp_idx = interp_idx;
		memcpy(&d->key, key, KEY_SIZE);
	} else {
		t_stub_32_data *d = stub_data;
		d->stub_virt_off = s->hdl.ph.get.vaddr(s, stub_idx);
		d->entry_point = s->hdl.eh.get.entry(s);
		d->ranges_ptr = s->hdl.ph.get.vaddr(s, prot_idx);
		d->ranges_len = s->hdl.ph.get.filesz(s, prot_idx) / sizeof(t_range);
		d->bss_ranges_ptr = s->hdl.ph.get.vaddr(s, bss_idx);
		d->bss_ranges_len = s->hdl.ph.get.filesz(s, bss_idx) / sizeof(t_range);
		d->interp_idx = interp_idx;
		memcpy(&d->key, key, KEY_SIZE);
	}
}

static int	_inject(
				t_elf_file *s,
				size_t first_entry_index,
				t_ranges *ranges,
				int interp_idx,
				const char *key) {
	t_ranges	bss_ranges = list_new();
	char		*stub_start;
	char		*stub_end;

	verbose("getting protected ranges...");
	if (!elf_get_protected_ranges(s, ranges))
		return (1);
	range_aggregate(ranges);
	verbose("%zu found !\n", ranges->len);

	verbose("getting bss ranges...");
	if (!elf_get_bss_vaddr_ranges(s, &bss_ranges))
		return (1);
	verbose("%zu found !\n", bss_ranges.len);

	stub_start = s->is_64 ? _binary_resources_stub64_bin_start : _binary_resources_stub32_bin_start;
	stub_end = s->is_64 ? _binary_resources_stub64_bin_end : _binary_resources_stub32_bin_end;

	verbose("append stub...");
	_append_segment(s, first_entry_index + PHT_IDX_STUB,
		stub_start, stub_end - stub_start, PF_X | PF_R | PF_W);
	verbose("done !\n");

	verbose("append bss ranges...");
	_append_segment(s, first_entry_index + PHT_IDX_BSS_RANGES,
		bss_ranges.data, (bss_ranges.len) * sizeof(*bss_ranges.data), PF_R);
	verbose("done !\n");

	list_free(&bss_ranges);
	list_push(ranges, MAKE_RANGE(0, 0));

	verbose("append protected ranges...");
	_append_segment(s, first_entry_index + PHT_IDX_PROTECTED_RANGES,
		ranges->data, ranges->len * sizeof(*ranges->data), PF_R);
	verbose("done !\n");

	verbose("populating stub data...");
	_populate_stub_data(s, first_entry_index, interp_idx, key);
	verbose("done !\n");

	list_push(ranges, MAKE_RANGE(s->hdl.ph.get.offset(s, first_entry_index), s->hdl.ph.get.offset(s, first_entry_index + PHT_IDX__NB - 1) + s->hdl.ph.get.memsz(s, first_entry_index + PHT_IDX__NB - 1) - s->hdl.ph.get.offset(s, first_entry_index)));
	range_aggregate(ranges);

	s->hdl.eh.set.entry(s, s->hdl.ph.get.vaddr(s, first_entry_index + PHT_IDX_STUB));
	return (0);
}

static void	_encrypt(
				t_elf_file *s,
				t_ranges *ranges,
				const char *key) {
	if (ranges->len == 0)
		return ; // MUST NEVER APPEND
	// xtea_encrypt((char *)s->data, ALIGN_DOWN(ranges->data[0].off, 8), (const uint32_t *)"1234567812345678");
	verbose("encrypt:\n");
	for (size_t k = 0; k < ranges->len - 1 && ranges->len != 0; ++k) {
		auto const	start_off = ALIGN_UP(ranges->data[k].off + ranges->data[k].len, 8);
		auto const	size = (off_t)ALIGN_DOWN(MIN(ranges->data[k + 1].off - (off_t)start_off, (off_t)(s->size - start_off)), 8);
		if (size <= 0)
			continue;
		xtea_encrypt((char *)s->data + start_off, size, (const uint32_t *)key);
		verbose("  %llx -> %llx\n", start_off, start_off + size - 1);
	}
	// auto const start_off = ALIGN_UP(ranges->data[ranges->len - 1].off + ranges->data[ranges->len - 1].len, 8);
	// xtea_encrypt((char *)s->data + start_off, ALIGN_DOWN((off_t)(s->size - start_off), 8), (const uint32_t *)"1234567812345678");
}

static noreturn void print_usage(void) {
	fprintf(stderr,
		"Usage: woody_woodpacker [-v] [-k key] EXEC\n"
		"  -v        verbose mode\n"
		"  -k key    encryption key (hex string, optional)\n"
	);
	exit(EXIT_FAILURE);
}

static bool				__str_is_hex(const char *s) {
	while (*s != '\0') {
		if (!(*s >= '0' && *s <= '9') && !(*s >= 'a' && *s <= 'f'))
			return (false);
		++s;
	}
	return (true);
}

static char				__from_hex(const char hex[2]) {
	char	r = 0;

	if (hex[0] >= 'a' && hex[0] <= 'f')
		r += 0xA + (hex[0] - 'a');
	else
		r += hex[0] - '0';
	r <<= 4;
	if (hex[1] >= 'a' && hex[1] <= 'f')
		r += 0xA + (hex[1] - 'a');
	else
		r += hex[1] - '0';
	return (r);
}

static char				*_key_from_str(const char *key) {
	char	*_key;

	if (strlen(key) != KEY_SIZE * 2 || !__str_is_hex(key))
		return (nullptr);
	_key = malloc(KEY_SIZE);
	if (_key == nullptr)
		return (nullptr);
	for (int k = 0; k < KEY_SIZE; ++k) {
		_key[k] = __from_hex(key + k * 2);
	}
	return (_key);
}
