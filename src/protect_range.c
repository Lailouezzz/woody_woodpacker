// ---
// Includes
// ---

#include "elf_reader.h"
#include "protect_range.h"

// ---
// Static function declarations
// ---

static bool	_elf_get_protected_ranges(
				const t_elf_file *elf,
				t_ranges *ranges
				);

static int	_range_cmp(
				const void *a,
				const void *b
				);

static void	_range_aggregate(
				t_ranges *ranges
				);

static bool	_add_ph_to_range(
				t_ranges *ranges,
				const t_elf_file *elf,
				size_t ph_index
				);

// ---
// Extern function definitions
// ---

bool	elf_get_protected_ranges(
			const t_elf_file *elf,
			t_ranges *ranges
			) {
	if (!_elf_get_protected_ranges(elf, ranges))
		return (false);
	quicksort(ranges->data, sizeof(*ranges->data), ranges->len, _range_cmp);
	_range_aggregate(ranges);
	return (true);
}

// ---
// Static function definitions
// ---

static bool	_elf_get_protected_ranges(
				const t_elf_file *elf,
				t_ranges *ranges
				) {
	static const uint32_t	_protected_types[] = {
		PT_DYNAMIC,
		PT_INTERP,
		PT_PHDR,
		PT_GNU_EH_FRAME,
		PT_GNU_PROPERTY,
	};
	const int	pt_dyn_idx = elf_find_ph_index(elf, elf_ph_is_dynamic);
	auto const	e_phnum = elf->hdl.eh.get.phnum(elf);

	if (!list_push(ranges, MAKE_RANGE(0x0, elf->is_64 ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr))))
		return (false);
	if (!list_push(ranges, MAKE_RANGE(elf->hdl.eh.get.phoff(elf), e_phnum * elf->hdl.eh.get.phentsize(elf))))
		return (false);
	for (typeof_unqual(e_phnum) k = 0; k < e_phnum; ++k)
		array_foreach(_protected_types, it)
			if (elf->hdl.ph.get.type(elf, k) == *it) 
				_add_ph_to_range(ranges, elf, k);
	if (pt_dyn_idx < 0) // No dynamics
		return (true);
	if (!_add_ph_to_range(ranges, elf, pt_dyn_idx))
		return (false);
	return (true);
}

static int	_range_cmp(
				const void *a,
				const void *b
				) {
	return (((const t_range *)b)->off - ((const t_range *)a)->off);
}

static void	_range_aggregate(
				t_ranges *ranges
				) {
	if (ranges->len == 0)
		return ;
	for (size_t k = 0; k < ranges->len - 1; ++k) {
		const off_t	last_off = ranges->data[k].off + ranges->data[k].len;
		const off_t	next_last_off = ranges->data[k + 1].off + ranges->data[k + 1].len;
		if (last_off >= ranges->data[k + 1].off) {
			ranges->data[k].len += next_last_off - last_off;
			list_delete(ranges, k + 1);
		}
	}
}

static bool	_add_ph_to_range(
				t_ranges *ranges,
				const t_elf_file *elf,
				size_t ph_index
				) {
	auto const	p_offset = elf->hdl.ph.get.offset(elf, ph_index);
	auto const	p_filesz = elf->hdl.ph.get.filesz(elf, ph_index);
	return list_push(ranges, MAKE_RANGE(p_offset, p_filesz));
}
