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

static bool	_add_ph_to_range(
				t_ranges *ranges,
				const t_elf_file *elf,
				size_t ph_index
				);

static bool	_add_bss_to_range(
				t_ranges *ranges,
				const t_elf_file *elf
				);

static bool _add_dyn_to_range(
				t_ranges *ranges,
				const t_elf_file *elf,
				size_t pt_dyn_idx
				);

static bool	_parse_dynamic(
				const t_elf_file *elf,
				size_t pt_dyn_idx,
				t_elf_dynamic *d
				);

static bool	_protect_rela_targets(
				t_ranges *ranges,
				const t_elf_file *elf,
				uint64_t rela_vaddr,
				uint64_t relasz,
				uint64_t relaent
				);

static bool	_protect_rel_targets(
				t_ranges *ranges,
				const t_elf_file *elf,
				uint64_t rel_vaddr,
				uint64_t relsz,
				uint64_t relent
				);

static bool	_protect_relr_targets(
				t_ranges *ranges,
				const t_elf_file *elf,
				uint64_t relr_vaddr,
				uint64_t relrsz,
				uint64_t relrent
				);

static size_t	_reloc_size_64(
					uint32_t type
					);

static size_t	_reloc_size_32(
					uint32_t type
					);

static bool	_protect_verneed(
				t_ranges *ranges,
				const t_elf_file *elf,
				uint64_t verneed_vaddr,
				uint64_t verneednum
				);

static bool	_protect_verdef(
				t_ranges *ranges,
				const t_elf_file *elf,
				uint64_t verdef_vaddr,
				uint64_t verdefnum);

// ---
// Extern function definitions
// ---

bool	elf_get_protected_ranges(
			const t_elf_file *elf,
			t_ranges *ranges
			) {
	if (!_elf_get_protected_ranges(elf, ranges))
		return (false);
	return (true);
}

bool	elf_get_bss_vaddr_ranges(
			const t_elf_file *elf,
			t_ranges *ranges
			) {
	for (size_t k = 0; k < elf->hdl.eh.get.phnum(elf); ++k) {
		auto const filesz = elf->hdl.ph.get.filesz(elf, k);
		auto const memsz = elf->hdl.ph.get.memsz(elf, k);
		if (filesz >= memsz || elf->hdl.ph.get.type(elf, k) != PT_LOAD)
			continue ;
		auto const vaddr = elf->hdl.ph.get.vaddr(elf, k);
		if (!list_push(ranges, MAKE_RANGE(vaddr + filesz, memsz - filesz)))
			return (false);
	}
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
		PT_GNU_RELRO,
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
	if (!_add_dyn_to_range(ranges, elf, pt_dyn_idx))
		return (false);
	if (!_add_bss_to_range(ranges, elf))
		return (false);
	return (true);
}

static int	_range_cmp(
				const void *a,
				const void *b
				) {
	return (((const t_range *)b)->off - ((const t_range *)a)->off);
}

void	range_aggregate(
			t_ranges *ranges
			) {
	if (ranges->len == 0)
		return ;
	quicksort(ranges->data, sizeof(*ranges->data), ranges->len, _range_cmp);
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

static bool	_add_bss_to_range(
				t_ranges *ranges,
				const t_elf_file *elf
				) {
	for (size_t k = 0; k < elf->hdl.eh.get.phnum(elf); ++k) {
		auto const filesz = elf->hdl.ph.get.filesz(elf, k);
		auto const memsz = elf->hdl.ph.get.memsz(elf, k);
		if (filesz >= memsz)
			continue ;
		auto const offset = elf->hdl.ph.get.offset(elf, k);
		if ((offset + filesz) % 4 == 0)
			continue ;
		auto const down_addr = ALIGN_DOWN(offset + filesz, 4);
		if (!list_push(ranges, MAKE_RANGE(down_addr, 4)))
			return (false);
	}
	return (true);
}

static bool	_add_dyn_to_range(
				t_ranges *ranges,
				const t_elf_file *elf,
				size_t pt_dyn_idx
				) {
	t_elf_dynamic	dyn = {0};
	const size_t	ptr_size = elf->is_64 ? 8 : 4;

	if (!_parse_dynamic(elf, pt_dyn_idx, &dyn))
		return (false);

	if (dyn.strtab && dyn.strsz) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.strtab);
		if (off && !list_push(ranges, MAKE_RANGE(off, dyn.strsz)))
			return (false);
	}

	if (dyn.symtab && dyn.strtab && dyn.strtab > dyn.symtab) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.symtab);
		if (off && !list_push(ranges, MAKE_RANGE(off, dyn.strtab - dyn.symtab)))
			return (false);
	}

	uint64_t nsyms = 0;
	if (dyn.symtab && dyn.strtab && dyn.syment)
		nsyms = (dyn.strtab - dyn.symtab) / dyn.syment;

	if (dyn.hash) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.hash);
		if (off) {
			const uint32_t *h = (const uint32_t *)((const char *)elf->data + off);
			uint32_t nbucket = h[0];
			uint32_t nchain = h[1];
			if (!list_push(ranges, MAKE_RANGE(off, (2 + nbucket + nchain) * sizeof(uint32_t))))
				return (false);
		}
	}

	if (dyn.gnu_hash) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.gnu_hash);
		if (off) {
			const uint32_t *gh = (const uint32_t *)((const char *)elf->data + off);
			uint32_t nbuckets = gh[0];
			uint32_t symndx = gh[1];
			uint32_t maskwords = gh[2];

			uint64_t chains_size = 0;
			if (nsyms > symndx)
				chains_size = (nsyms - symndx) * sizeof(uint32_t);

			uint64_t total = 16 + maskwords * ptr_size + nbuckets * 4 + chains_size;

			if (!list_push(ranges, MAKE_RANGE(off, total)))
				return (false);
		}
	}

	if (dyn.rela && dyn.relasz) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.rela);
		if (off && !list_push(ranges, MAKE_RANGE(off, dyn.relasz)))
			return (false);
	}

	if (dyn.rel && dyn.relsz) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.rel);
		if (off && !list_push(ranges, MAKE_RANGE(off, dyn.relsz)))
			return (false);
	}

	if (dyn.jmprel && dyn.pltrelsz) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.jmprel);
		if (off && !list_push(ranges, MAKE_RANGE(off, dyn.pltrelsz)))
			return (false);
	}

	if (dyn.relr && dyn.relrsz) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.relr);
		if (off && !list_push(ranges, MAKE_RANGE(off, dyn.relrsz)))
			return (false);
	}

	if (dyn.pltgot) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.pltgot);
		if (!list_push(ranges, MAKE_RANGE(off, ptr_size * 3)))
			return (false);
	}

	if (!_protect_rela_targets(ranges, elf, dyn.rela, dyn.relasz, dyn.relaent))
		return (false);
	if (!_protect_rel_targets(ranges, elf, dyn.rel, dyn.relsz, dyn.relent))
		return (false);
	if (!_protect_relr_targets(ranges, elf, dyn.relr, dyn.relrsz, dyn.relrent))
		return (false);

	if (dyn.jmprel && dyn.pltrelsz) {
		if (dyn.pltrel == DT_RELA && !_protect_rela_targets(ranges, elf, dyn.jmprel, dyn.pltrelsz, dyn.relaent))
			return (false);
		else if (!_protect_rel_targets(ranges, elf, dyn.jmprel, dyn.pltrelsz, dyn.relent))
			return (false);
	}

	if (dyn.init) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.init);
		if (off && !list_push(ranges, MAKE_RANGE(off, ptr_size)))
			return (false);
	}

	if (dyn.fini) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.fini);
		if (off && !list_push(ranges, MAKE_RANGE(off, ptr_size)))
			return (false);
	}

	if (dyn.init_array && dyn.init_arraysz) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.init_array);
		if (off && !list_push(ranges, MAKE_RANGE(off, dyn.init_arraysz)))
			return (false);
	}

	if (dyn.fini_array && dyn.fini_arraysz) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.fini_array);
		if (off && !list_push(ranges, MAKE_RANGE(off, dyn.fini_arraysz)))
			return (false);
	}

	if (dyn.preinit_array && dyn.preinit_arraysz) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.preinit_array);
		if (off && !list_push(ranges, MAKE_RANGE(off, dyn.preinit_arraysz)))
			return (false);
	}

	if (dyn.versym && nsyms) {
		uint64_t off = elf_vaddr_to_offset(elf, dyn.versym);
		if (off)
			list_push(ranges, MAKE_RANGE(off, nsyms * sizeof(uint16_t)));
	}

	_protect_verneed(ranges, elf, dyn.verneed, dyn.verneednum);
	_protect_verdef(ranges, elf, dyn.verdef, dyn.verdefnum);
	return (true);
}

static bool	_parse_dynamic(
				const t_elf_file *elf,
				size_t pt_dyn_idx,
				t_elf_dynamic *d
				) {
	auto const	pt_dyn_off = elf->hdl.ph.get.offset(elf, pt_dyn_idx);
	if (elf->is_64) {
		const Elf64_Dyn *dyn = (const Elf64_Dyn *)((const char *)elf->data + pt_dyn_off);

		for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
			switch (dyn[i].d_tag) {
			/* String/Symbol tables */
			case DT_STRTAB:        d->strtab = dyn[i].d_un.d_ptr; break ;
			case DT_STRSZ:         d->strsz = dyn[i].d_un.d_val; break ;
			case DT_SYMTAB:        d->symtab = dyn[i].d_un.d_ptr; break ;
			case DT_SYMENT:        d->syment = dyn[i].d_un.d_val; break ;

			/* Hash tables */
			case DT_HASH:          d->hash = dyn[i].d_un.d_ptr; break ;
			case DT_GNU_HASH:      d->gnu_hash = dyn[i].d_un.d_ptr; break ;

			/* RELA relocations */
			case DT_RELA:          d->rela = dyn[i].d_un.d_ptr; break ;
			case DT_RELASZ:        d->relasz = dyn[i].d_un.d_val; break ;
			case DT_RELAENT:       d->relaent = dyn[i].d_un.d_val; break ;

			/* REL relocations */
			case DT_REL:           d->rel = dyn[i].d_un.d_ptr; break ;
			case DT_RELSZ:         d->relsz = dyn[i].d_un.d_val; break ;
			case DT_RELENT:        d->relent = dyn[i].d_un.d_val; break ;

			/* PLT relocations */
			case DT_JMPREL:        d->jmprel = dyn[i].d_un.d_ptr; break ;
			case DT_PLTRELSZ:      d->pltrelsz = dyn[i].d_un.d_val; break ;
			case DT_PLTREL:        d->pltrel = dyn[i].d_un.d_val; break ;

			/* RELR relocations */
			case DT_RELR:          d->relr = dyn[i].d_un.d_ptr; break ;
			case DT_RELRSZ:        d->relrsz = dyn[i].d_un.d_val; break ;
			case DT_RELRENT:       d->relrent = dyn[i].d_un.d_val; break ;

			/* Init/Fini */
			case DT_INIT:          d->init = dyn[i].d_un.d_ptr; break ;
			case DT_FINI:          d->fini = dyn[i].d_un.d_ptr; break ;
			case DT_INIT_ARRAY:    d->init_array = dyn[i].d_un.d_ptr; break ;
			case DT_INIT_ARRAYSZ:  d->init_arraysz = dyn[i].d_un.d_val; break ;
			case DT_FINI_ARRAY:    d->fini_array = dyn[i].d_un.d_ptr; break ;
			case DT_FINI_ARRAYSZ:  d->fini_arraysz = dyn[i].d_un.d_val; break ;
			case DT_PREINIT_ARRAY: d->preinit_array = dyn[i].d_un.d_ptr; break ;
			case DT_PREINIT_ARRAYSZ: d->preinit_arraysz = dyn[i].d_un.d_val; break ;

			/* Versioning */
			case DT_VERSYM:        d->versym = dyn[i].d_un.d_ptr; break ;
			case DT_VERNEED:       d->verneed = dyn[i].d_un.d_ptr; break ;
			case DT_VERNEEDNUM:    d->verneednum = dyn[i].d_un.d_val; break ;
			case DT_VERDEF:        d->verdef = dyn[i].d_un.d_ptr; break ;
			case DT_VERDEFNUM:     d->verdefnum = dyn[i].d_un.d_val; break ;

			/* GOT/PLT */
			case DT_PLTGOT:        d->pltgot = dyn[i].d_un.d_ptr; break ;

			/* Flags */
			case DT_FLAGS:
				d->flags = dyn[i].d_un.d_val;
				if (d->flags & DF_TEXTREL)
					d->has_textrel = true;
				break ;
			case DT_FLAGS_1:
				d->flags_1 = dyn[i].d_un.d_val;
				break ;
			case DT_TEXTREL:
				d->has_textrel = true;
				break ;
			default:
				break ;
			}
		}

		if (!d->relaent) d->relaent = sizeof(Elf64_Rela);
		if (!d->relent)  d->relent = sizeof(Elf64_Rel);
		if (!d->relrent) d->relrent = sizeof(uint64_t);
		if (!d->syment)  d->syment = sizeof(Elf64_Sym);
	} else {
		const Elf32_Dyn *dyn = (const Elf32_Dyn *)((const char *)elf->data + pt_dyn_off);

		for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
			switch (dyn[i].d_tag) {
			/* String/Symbol tables */
			case DT_STRTAB:        d->strtab = dyn[i].d_un.d_ptr; break ;
			case DT_STRSZ:         d->strsz = dyn[i].d_un.d_val; break ;
			case DT_SYMTAB:        d->symtab = dyn[i].d_un.d_ptr; break ;
			case DT_SYMENT:        d->syment = dyn[i].d_un.d_val; break ;

			/* Hash tables */
			case DT_HASH:          d->hash = dyn[i].d_un.d_ptr; break ;
			case DT_GNU_HASH:      d->gnu_hash = dyn[i].d_un.d_ptr; break ;

			/* RELA relocations */
			case DT_RELA:          d->rela = dyn[i].d_un.d_ptr; break ;
			case DT_RELASZ:        d->relasz = dyn[i].d_un.d_val; break ;
			case DT_RELAENT:       d->relaent = dyn[i].d_un.d_val; break ;

			/* REL relocations */
			case DT_REL:           d->rel = dyn[i].d_un.d_ptr; break ;
			case DT_RELSZ:         d->relsz = dyn[i].d_un.d_val; break ;
			case DT_RELENT:        d->relent = dyn[i].d_un.d_val; break ;

			/* PLT relocations */
			case DT_JMPREL:        d->jmprel = dyn[i].d_un.d_ptr; break ;
			case DT_PLTRELSZ:      d->pltrelsz = dyn[i].d_un.d_val; break ;
			case DT_PLTREL:        d->pltrel = dyn[i].d_un.d_val; break ;

			/* Init/Fini */
			case DT_INIT:          d->init = dyn[i].d_un.d_ptr; break ;
			case DT_FINI:          d->fini = dyn[i].d_un.d_ptr; break ;
			case DT_INIT_ARRAY:    d->init_array = dyn[i].d_un.d_ptr; break ;
			case DT_INIT_ARRAYSZ:  d->init_arraysz = dyn[i].d_un.d_val; break ;
			case DT_FINI_ARRAY:    d->fini_array = dyn[i].d_un.d_ptr; break ;
			case DT_FINI_ARRAYSZ:  d->fini_arraysz = dyn[i].d_un.d_val; break ;
			case DT_PREINIT_ARRAY: d->preinit_array = dyn[i].d_un.d_ptr; break ;
			case DT_PREINIT_ARRAYSZ: d->preinit_arraysz = dyn[i].d_un.d_val; break ;

			/* Versioning */
			case DT_VERSYM:        d->versym = dyn[i].d_un.d_ptr; break ;
			case DT_VERNEED:       d->verneed = dyn[i].d_un.d_ptr; break ;
			case DT_VERNEEDNUM:    d->verneednum = dyn[i].d_un.d_val; break ;
			case DT_VERDEF:        d->verdef = dyn[i].d_un.d_ptr; break ;
			case DT_VERDEFNUM:     d->verdefnum = dyn[i].d_un.d_val; break ;

			/* GOT/PLT */
			case DT_PLTGOT:        d->pltgot = dyn[i].d_un.d_ptr; break ;

			/* Flags */
			case DT_FLAGS:
				d->flags = dyn[i].d_un.d_val;
				if (d->flags & DF_TEXTREL)
					d->has_textrel = true;
				break ;
			case DT_FLAGS_1:
				d->flags_1 = dyn[i].d_un.d_val;
				break ;
			case DT_TEXTREL:
				d->has_textrel = true;
				break ;
			}
		}

		if (!d->relaent) d->relaent = sizeof(Elf32_Rela);
		if (!d->relent)  d->relent = sizeof(Elf32_Rel);
		if (!d->relrent) d->relrent = sizeof(uint32_t);
		if (!d->syment)  d->syment = sizeof(Elf32_Sym);
	}
	return (true);
}

static bool	_protect_rela_targets(
				t_ranges *ranges,
				const t_elf_file *elf,
				uint64_t rela_vaddr,
				uint64_t relasz,
				uint64_t relaent
				) {
	if (!rela_vaddr || !relasz)
		return (true);

	uint64_t rela_off = elf_vaddr_to_offset(elf, rela_vaddr);
	if (!rela_off)
		return (true);

	size_t count = relasz / relaent;

	if (elf->is_64) {
		const Elf64_Rela *rela = (const Elf64_Rela *)(elf->data + rela_off);
		for (size_t i = 0; i < count; i++) {
			uint64_t target_off = elf_vaddr_to_offset(elf, rela[i].r_offset);
			if (target_off) {
				uint32_t type = ELF64_R_TYPE(rela[i].r_info);
				if (!list_push(ranges, MAKE_RANGE(target_off, _reloc_size_64(type))))
					return (false);
			}
		}
	} else {
		const Elf32_Rela *rela = (const Elf32_Rela *)(elf->data + rela_off);
		for (size_t i = 0; i < count; i++) {
			uint64_t target_off = elf_vaddr_to_offset(elf, rela[i].r_offset);
			if (target_off) {
				uint32_t type = ELF32_R_TYPE(rela[i].r_info);
				if (!list_push(ranges, MAKE_RANGE(target_off, _reloc_size_32(type))))
					return (false);
			}
		}
	}
	return (true);
}

static bool	_protect_rel_targets(
				t_ranges *ranges,
				const t_elf_file *elf,
				uint64_t rel_vaddr,
				uint64_t relsz,
				uint64_t relent
				) {
	if (!rel_vaddr || !relsz)
		return (true);

	uint64_t rel_off = elf_vaddr_to_offset(elf, rel_vaddr);
	if (!rel_off)
		return (true);

	size_t count = relsz / relent;

	if (elf->is_64) {
		const Elf64_Rel *rel = (const Elf64_Rel *)(elf->data + rel_off);
		for (size_t i = 0; i < count; i++) {
			uint64_t target_off = elf_vaddr_to_offset(elf, rel[i].r_offset);
			if (target_off) {
				uint32_t type = ELF64_R_TYPE(rel[i].r_info);
				if (!list_push(ranges, MAKE_RANGE(target_off, _reloc_size_64(type))))
					return (false);
			}
		}
	} else {
		const Elf32_Rel *rel = (const Elf32_Rel *)(elf->data + rel_off);
		for (size_t i = 0; i < count; i++) {
			uint64_t target_off = elf_vaddr_to_offset(elf, rel[i].r_offset);
			if (target_off) {
				uint32_t type = ELF32_R_TYPE(rel[i].r_info);
				if (!list_push(ranges, MAKE_RANGE(target_off, _reloc_size_32(type))))
					return (false);
			}
		}
	}
	return (true);
}

static bool	_protect_relr_targets(
				t_ranges *ranges,
				const t_elf_file *elf,
				uint64_t relr_vaddr,
				uint64_t relrsz,
				uint64_t relrent
				) {
	if (!relr_vaddr || !relrsz)
		return (true);

	uint64_t relr_off = elf_vaddr_to_offset(elf, relr_vaddr);
	if (!relr_off)
		return (true);

	size_t count = relrsz / relrent;
	uint64_t base = 0;

	if (elf->is_64) {
		const uint64_t *relr = (const uint64_t *)(elf->data + relr_off);
		for (size_t i = 0; i < count; i++) {
			uint64_t entry = relr[i];
			if ((entry & 1) == 0) {
				/* Direct address */
				uint64_t target_off = elf_vaddr_to_offset(elf, entry);
				if (target_off && !list_push(ranges, MAKE_RANGE(target_off, 8)))
					return (false);
				base = entry + 8;
			} else {
				/* Bitmap: each bit represents 8-byte slot */
				uint64_t bitmap = entry >> 1;
				for (int j = 0; bitmap; j++, bitmap >>= 1) {
					if (bitmap & 1) {
						uint64_t target_off = elf_vaddr_to_offset(elf, base + j * 8);
						if (target_off && !list_push(ranges, MAKE_RANGE(target_off, 8)))
							return (false);
					}
				}
				base += 63 * 8;
			}
		}
	} else {
		const uint32_t *relr = (const uint32_t *)(elf->data + relr_off);
		for (size_t i = 0; i < count; i++) {
			uint32_t entry = relr[i];
			if ((entry & 1) == 0) {
				/* Direct address */
				uint64_t target_off = elf_vaddr_to_offset(elf, entry);
				if (target_off && !list_push(ranges, MAKE_RANGE(target_off, 4)))
					return (false);
				base = entry + 4;
			} else {
				/* Bitmap: each bit represents 4-byte slot */
				uint32_t bitmap = entry >> 1;
				for (int j = 0; bitmap; j++, bitmap >>= 1) {
					if (bitmap & 1) {
						uint64_t target_off = elf_vaddr_to_offset(elf, base + j * 4);
						if (target_off && !list_push(ranges, MAKE_RANGE(target_off, 4)))
							return (false);
					}
				}
				base += 31 * 4;
			}
		}
	}
	return (true);
}

static size_t	_reloc_size_64(
					uint32_t type
					) {
	switch (type) {
	case R_X86_64_64:
	case R_X86_64_GLOB_DAT:
	case R_X86_64_JUMP_SLOT:
	case R_X86_64_RELATIVE:
	case R_X86_64_DTPMOD64:
	case R_X86_64_DTPOFF64:
	case R_X86_64_TPOFF64:
	case R_X86_64_IRELATIVE:
		return 8;

	case R_X86_64_32:
	case R_X86_64_32S:
	case R_X86_64_PC32:
	case R_X86_64_GOT32:
	case R_X86_64_PLT32:
	case R_X86_64_GOTPC32:
	case R_X86_64_GOTPCREL:
	case R_X86_64_TLSGD:
	case R_X86_64_TLSLD:
	case R_X86_64_GOTTPOFF:
		return 4;

	case R_X86_64_16:
	case R_X86_64_PC16:
		return 2;

	case R_X86_64_8:
	case R_X86_64_PC8:
		return 1;

	default:
		return 8;
	}
}

static size_t	_reloc_size_32(
					uint32_t type
					) {
	switch (type) {
	case R_386_32:
	case R_386_PC32:
	case R_386_GOT32:
	case R_386_PLT32:
	case R_386_GLOB_DAT:
	case R_386_JMP_SLOT:
	case R_386_RELATIVE:
	case R_386_GOTOFF:
	case R_386_GOTPC:
	case R_386_TLS_TPOFF:
	case R_386_TLS_DTPMOD32:
	case R_386_TLS_DTPOFF32:
	case R_386_IRELATIVE:
		return 4;

	case R_386_16:
	case R_386_PC16:
		return 2;

	case R_386_8:
	case R_386_PC8:
		return 1;

	default:
		return 4;
	}
}

static bool	_protect_verneed(
				t_ranges *ranges,
				const t_elf_file *elf,
				uint64_t verneed_vaddr,
				uint64_t verneednum
				) {
	if (!verneed_vaddr || !verneednum)
		return (true);

	uint64_t off = elf_vaddr_to_offset(elf, verneed_vaddr);
	if (!off)
		return (true);

	uint8_t *start = elf->data + off;
	uint8_t *end = start;

	if (elf->is_64) {
		Elf64_Verneed *vn = (Elf64_Verneed *)start;
		for (uint64_t i = 0; i < verneednum; i++) {
			Elf64_Vernaux *vna = (Elf64_Vernaux *)((uint8_t *)vn + vn->vn_aux);
			for (int j = 0; j < vn->vn_cnt; j++) {
				uint8_t *aux_end = (uint8_t *)vna + sizeof(Elf64_Vernaux);
				if (aux_end > end)
					end = aux_end;
				if (vna->vna_next == 0)
					break;
				vna = (Elf64_Vernaux *)((uint8_t *)vna + vna->vna_next);
			}
			if (vn->vn_next == 0)
				break;
			vn = (Elf64_Verneed *)((uint8_t *)vn + vn->vn_next);
		}
	} else {
		Elf32_Verneed *vn = (Elf32_Verneed *)start;
		for (uint64_t i = 0; i < verneednum; i++) {
			Elf32_Vernaux *vna = (Elf32_Vernaux *)((uint8_t *)vn + vn->vn_aux);
			for (int j = 0; j < vn->vn_cnt; j++) {
				uint8_t *aux_end = (uint8_t *)vna + sizeof(Elf32_Vernaux);
				if (aux_end > end)
					end = aux_end;
				if (vna->vna_next == 0)
					break;
				vna = (Elf32_Vernaux *)((uint8_t *)vna + vna->vna_next);
			}
			if (vn->vn_next == 0)
				break;
			vn = (Elf32_Verneed *)((uint8_t *)vn + vn->vn_next);
		}
	}

	return (list_push(ranges, MAKE_RANGE(off, end - start)));
}

static bool	_protect_verdef(
				t_ranges *ranges,
				const t_elf_file *elf,
				uint64_t verdef_vaddr,
				uint64_t verdefnum) {
	if (!verdef_vaddr || !verdefnum)
		return (true);

	uint64_t off = elf_vaddr_to_offset(elf, verdef_vaddr);
	if (!off)
		return (true);

	uint8_t *start = elf->data + off;
	uint8_t *end = start;

	if (elf->is_64) {
		Elf64_Verdef *vd = (Elf64_Verdef *)start;
		for (uint64_t i = 0; i < verdefnum; i++) {
			Elf64_Verdaux *vda = (Elf64_Verdaux *)((uint8_t *)vd + vd->vd_aux);
			for (int j = 0; j < vd->vd_cnt; j++) {
				uint8_t *aux_end = (uint8_t *)vda + sizeof(Elf64_Verdaux);
				if (aux_end > end)
					end = aux_end;
				if (vda->vda_next == 0)
					break;
				vda = (Elf64_Verdaux *)((uint8_t *)vda + vda->vda_next);
			}
			if (vd->vd_next == 0)
				break;
			vd = (Elf64_Verdef *)((uint8_t *)vd + vd->vd_next);
		}
	} else {
		Elf32_Verdef *vd = (Elf32_Verdef *)start;
		for (uint64_t i = 0; i < verdefnum; i++) {
			Elf32_Verdaux *vda = (Elf32_Verdaux *)((uint8_t *)vd + vd->vd_aux);
			for (int j = 0; j < vd->vd_cnt; j++) {
				uint8_t *aux_end = (uint8_t *)vda + sizeof(Elf32_Verdaux);
				if (aux_end > end)
					end = aux_end;
				if (vda->vda_next == 0)
					break;
				vda = (Elf32_Verdaux *)((uint8_t *)vda + vda->vda_next);
			}
			if (vd->vd_next == 0)
				break;
			vd = (Elf32_Verdef *)((uint8_t *)vd + vd->vd_next);
		}
	}

	return (list_push(ranges, MAKE_RANGE(off, end - start)));
}

