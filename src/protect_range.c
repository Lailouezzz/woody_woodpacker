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

static bool	_parse_dyn(
				t_ranges *ranges,
				const t_elf_file *elf,
				int pt_dyn_idx
				);

static bool	_parse_pt_dyn(
				const t_elf_file *elf,
				int pt_dyn_idx,
				t_elf_dynamic *elf_dyn
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
	auto const	shstrndx = elf->hdl.eh.get.shstrndx(elf);
	auto const	e_phnum = elf->hdl.eh.get.phnum(elf);
	auto const	e_shnum = elf->hdl.eh.get.shnum(elf);

	if (!list_push(ranges, MAKE_RANGE(0x0, elf->is_64 ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr))))
		return (false);
	if (!list_push(ranges, MAKE_RANGE(elf->hdl.eh.get.phoff(elf), e_phnum * elf->hdl.eh.get.phentsize(elf))))
		return (false);
	if (!list_push(ranges, MAKE_RANGE(elf->hdl.eh.get.shoff(elf), e_shnum * elf->hdl.eh.get.shentsize(elf))))
		return (false);
	if (!list_push(ranges, MAKE_RANGE(elf->hdl.sh.get.offset(elf, shstrndx), elf->hdl.sh.get.size(elf, shstrndx))))
		return (false);
	for (typeof_unqual(e_phnum) k = 0; k < e_phnum; ++k)
		array_foreach(_protected_types, it)
			if (elf->hdl.ph.get.type(elf, k) == *it) 
				_add_ph_to_range(ranges, elf, k);
	if (pt_dyn_idx < 0) // No dynamics
		return (true);
	if (!_add_ph_to_range(ranges, elf, pt_dyn_idx))
		return (false);
	if (!_parse_dyn(ranges, elf, pt_dyn_idx))
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
			if (next_last_off > last_off)
				ranges->data[k].len += next_last_off - last_off;
			list_delete(ranges, k + 1);
			--k;
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

static bool	_parse_dyn(
				t_ranges *ranges,
				const t_elf_file *elf,
				int pt_dyn_idx
				) {
	t_elf_dynamic	elf_dyn = {0};

	if (!_parse_pt_dyn(elf, pt_dyn_idx, &elf_dyn))
		return (false);
	UNUSED(ranges);
	return (true);
}

static bool	_parse_pt_dyn(
				const t_elf_file *elf,
				int pt_dyn_idx,
				t_elf_dynamic *elf_dyn
				) {
	auto const	dyn_off = elf->hdl.ph.get.offset(elf, pt_dyn_idx);

	if (elf->is_64) {
		const Elf64_Dyn *dyn = (const Elf64_Dyn *)(elf->data + dyn_off);

		for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
			switch (dyn[i].d_tag) {
			/* String/Symbol tables */
			case DT_STRTAB:            elf_dyn->strtab = dyn[i].d_un.d_ptr; break;
			case DT_STRSZ:             elf_dyn->strsz = dyn[i].d_un.d_val; break;
			case DT_SYMTAB:            elf_dyn->symtab = dyn[i].d_un.d_ptr; break;
			case DT_SYMENT:            elf_dyn->syment = dyn[i].d_un.d_val; break;

			/* Hash tables */
			case DT_HASH:              elf_dyn->hash = dyn[i].d_un.d_ptr; break;
			case DT_GNU_HASH:          elf_dyn->gnu_hash = dyn[i].d_un.d_ptr; break;

			/* RELA relocations */
			case DT_RELA:              elf_dyn->rela = dyn[i].d_un.d_ptr; break;
			case DT_RELASZ:            elf_dyn->relasz = dyn[i].d_un.d_val; break;
			case DT_RELAENT:           elf_dyn->relaent = dyn[i].d_un.d_val; break;

			/* REL relocations */
			case DT_REL:               elf_dyn->rel = dyn[i].d_un.d_ptr; break;
			case DT_RELSZ:             elf_dyn->relsz = dyn[i].d_un.d_val; break;
			case DT_RELENT:            elf_dyn->relent = dyn[i].d_un.d_val; break;

			/* PLT relocations */
			case DT_JMPREL:            elf_dyn->jmprel = dyn[i].d_un.d_ptr; break;
			case DT_PLTRELSZ:          elf_dyn->pltrelsz = dyn[i].d_un.d_val; break;
			case DT_PLTREL:            elf_dyn->pltrel = dyn[i].d_un.d_val; break;

			/* RELR relocations */
			case DT_RELR:              elf_dyn->relr = dyn[i].d_un.d_ptr; break;
			case DT_RELRSZ:            elf_dyn->relrsz = dyn[i].d_un.d_val; break;
			case DT_RELRENT:           elf_dyn->relrent = dyn[i].d_un.d_val; break;

			/* Init/Fini */
			case DT_INIT:              elf_dyn->init = dyn[i].d_un.d_ptr; break;
			case DT_FINI:              elf_dyn->fini = dyn[i].d_un.d_ptr; break;
			case DT_INIT_ARRAY:        elf_dyn->init_array = dyn[i].d_un.d_ptr; break;
			case DT_INIT_ARRAYSZ:      elf_dyn->init_arraysz = dyn[i].d_un.d_val; break;
			case DT_FINI_ARRAY:        elf_dyn->fini_array = dyn[i].d_un.d_ptr; break;
			case DT_FINI_ARRAYSZ:      elf_dyn->fini_arraysz = dyn[i].d_un.d_val; break;
			case DT_PREINIT_ARRAY:     elf_dyn->preinit_array = dyn[i].d_un.d_ptr; break;
			case DT_PREINIT_ARRAYSZ:   elf_dyn->preinit_arraysz = dyn[i].d_un.d_val; break;

			/* Versioning */
			case DT_VERSYM:            elf_dyn->versym = dyn[i].d_un.d_ptr; break;
			case DT_VERNEED:           elf_dyn->verneed = dyn[i].d_un.d_ptr; break;
			case DT_VERNEEDNUM:        elf_dyn->verneednum = dyn[i].d_un.d_val; break;
			case DT_VERDEF:            elf_dyn->verdef = dyn[i].d_un.d_ptr; break;
			case DT_VERDEFNUM:         elf_dyn->verdefnum = dyn[i].d_un.d_val; break;

			/* GOT/PLT */
			case DT_PLTGOT:            elf_dyn->pltgot = dyn[i].d_un.d_ptr; break;

			/* Flags */
			case DT_FLAGS:
				elf_dyn->flags = dyn[i].d_un.d_val;
				if (elf_dyn->flags & DF_TEXTREL)
					elf_dyn->has_textrel = true;
				break;
			case DT_FLAGS_1:
				elf_dyn->flags_1 = dyn[i].d_un.d_val;
				break;
			case DT_TEXTREL:
				elf_dyn->has_textrel = true;
				break;
			}
		}

		/* Default entry sizes for 64-bit */
		if (!elf_dyn->relaent) elf_dyn->relaent = sizeof(Elf64_Rela);
		if (!elf_dyn->relent)  elf_dyn->relent = sizeof(Elf64_Rel);
		if (!elf_dyn->relrent) elf_dyn->relrent = sizeof(uint64_t);
		if (!elf_dyn->syment)  elf_dyn->syment = sizeof(Elf64_Sym);
	} else {
		const Elf32_Dyn *dyn = (const Elf32_Dyn *)(elf->data + dyn_off);

		for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
			switch (dyn[i].d_tag) {
			/* String/Symbol tables */
			case DT_STRTAB:            elf_dyn->strtab = dyn[i].d_un.d_ptr; break;
			case DT_STRSZ:             elf_dyn->strsz = dyn[i].d_un.d_val; break;
			case DT_SYMTAB:            elf_dyn->symtab = dyn[i].d_un.d_ptr; break;
			case DT_SYMENT:            elf_dyn->syment = dyn[i].d_un.d_val; break;

			/* Hash tables */
			case DT_HASH:              elf_dyn->hash = dyn[i].d_un.d_ptr; break;
			case DT_GNU_HASH:          elf_dyn->gnu_hash = dyn[i].d_un.d_ptr; break;

			/* RELA relocations */
			case DT_RELA:              elf_dyn->rela = dyn[i].d_un.d_ptr; break;
			case DT_RELASZ:            elf_dyn->relasz = dyn[i].d_un.d_val; break;
			case DT_RELAENT:           elf_dyn->relaent = dyn[i].d_un.d_val; break;

			/* REL relocations */
			case DT_REL:               elf_dyn->rel = dyn[i].d_un.d_ptr; break;
			case DT_RELSZ:             elf_dyn->relsz = dyn[i].d_un.d_val; break;
			case DT_RELENT:            elf_dyn->relent = dyn[i].d_un.d_val; break;

			/* PLT relocations */
			case DT_JMPREL:            elf_dyn->jmprel = dyn[i].d_un.d_ptr; break;
			case DT_PLTRELSZ:          elf_dyn->pltrelsz = dyn[i].d_un.d_val; break;
			case DT_PLTREL:            elf_dyn->pltrel = dyn[i].d_un.d_val; break;

			/* Init/Fini */
			case DT_INIT:              elf_dyn->init = dyn[i].d_un.d_ptr; break;
			case DT_FINI:              elf_dyn->fini = dyn[i].d_un.d_ptr; break;
			case DT_INIT_ARRAY:        elf_dyn->init_array = dyn[i].d_un.d_ptr; break;
			case DT_INIT_ARRAYSZ:      elf_dyn->init_arraysz = dyn[i].d_un.d_val; break;
			case DT_FINI_ARRAY:        elf_dyn->fini_array = dyn[i].d_un.d_ptr; break;
			case DT_FINI_ARRAYSZ:      elf_dyn->fini_arraysz = dyn[i].d_un.d_val; break;
			case DT_PREINIT_ARRAY:     elf_dyn->preinit_array = dyn[i].d_un.d_ptr; break;
			case DT_PREINIT_ARRAYSZ:   elf_dyn->preinit_arraysz = dyn[i].d_un.d_val; break;

			/* Versioning */
			case DT_VERSYM:            elf_dyn->versym = dyn[i].d_un.d_ptr; break;
			case DT_VERNEED:           elf_dyn->verneed = dyn[i].d_un.d_ptr; break;
			case DT_VERNEEDNUM:        elf_dyn->verneednum = dyn[i].d_un.d_val; break;
			case DT_VERDEF:            elf_dyn->verdef = dyn[i].d_un.d_ptr; break;
			case DT_VERDEFNUM:         elf_dyn->verdefnum = dyn[i].d_un.d_val; break;

			/* GOT/PLT */
			case DT_PLTGOT:            elf_dyn->pltgot = dyn[i].d_un.d_ptr; break;

			/* Flags */
			case DT_FLAGS:
				elf_dyn->flags = dyn[i].d_un.d_val;
				if (elf_dyn->flags & DF_TEXTREL)
					elf_dyn->has_textrel = true;
				break;
			case DT_FLAGS_1:
				elf_dyn->flags_1 = dyn[i].d_un.d_val;
				break;
			case DT_TEXTREL:
				elf_dyn->has_textrel = true;
				break;
			}
		}

		/* Default entry sizes for 32-bit */
		if (!elf_dyn->relaent) elf_dyn->relaent = sizeof(Elf32_Rela);
		if (!elf_dyn->relent)  elf_dyn->relent = sizeof(Elf32_Rel);
		if (!elf_dyn->relrent) elf_dyn->relrent = sizeof(uint32_t);
		if (!elf_dyn->syment)  elf_dyn->syment = sizeof(Elf32_Sym);

	}
	return (true);
}
