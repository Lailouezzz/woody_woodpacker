/**
 * @file elf_protected.c
 * @brief Implementation of ELF protected range detection.
 */

#include "elf_protected.h"
#include "elf_dynamic.h"

#include <stdlib.h>
#include <string.h>

/* ========================================================================== */
/*                              Private helpers                               */
/* ========================================================================== */

/**
 * @brief Add a range to the protected list.
 */
static void list_add(elf_protected_list_t *list, uint64_t offset, uint64_t size)
{
	if (size == 0)
		return;

	if (list->count >= list->cap) {
		list->cap = list->cap ? list->cap * 2 : 64;
		list->ranges = realloc(list->ranges, list->cap * sizeof(elf_range_t));
	}

	list->ranges[list->count++] = (elf_range_t){
		.offset = offset,
		.size = size
	};
}

/* ========================================================================== */
/*                          Program header accessors                          */
/* ========================================================================== */

static uint32_t phdr_type(const elf_info_t *info, int idx)
{
	if (info->is_64) {
		const Elf64_Phdr *phdr = (const Elf64_Phdr *)(info->data + info->phoff);
		return phdr[idx].p_type;
	}
	const Elf32_Phdr *phdr = (const Elf32_Phdr *)(info->data + info->phoff);
	return phdr[idx].p_type;
}

static uint64_t phdr_offset(const elf_info_t *info, int idx)
{
	if (info->is_64) {
		const Elf64_Phdr *phdr = (const Elf64_Phdr *)(info->data + info->phoff);
		return phdr[idx].p_offset;
	}
	const Elf32_Phdr *phdr = (const Elf32_Phdr *)(info->data + info->phoff);
	return phdr[idx].p_offset;
}

static uint64_t phdr_vaddr(const elf_info_t *info, int idx)
{
	if (info->is_64) {
		const Elf64_Phdr *phdr = (const Elf64_Phdr *)(info->data + info->phoff);
		return phdr[idx].p_vaddr;
	}
	const Elf32_Phdr *phdr = (const Elf32_Phdr *)(info->data + info->phoff);
	return phdr[idx].p_vaddr;
}

static uint64_t phdr_filesz(const elf_info_t *info, int idx)
{
	if (info->is_64) {
		const Elf64_Phdr *phdr = (const Elf64_Phdr *)(info->data + info->phoff);
		return phdr[idx].p_filesz;
	}
	const Elf32_Phdr *phdr = (const Elf32_Phdr *)(info->data + info->phoff);
	return phdr[idx].p_filesz;
}

/* ========================================================================== */
/*                             Dynamic parsing                                */
/* ========================================================================== */

/**
 * @brief Parse PT_DYNAMIC segment.
 */
static elf_dynamic_t parse_dynamic(const elf_info_t *info, uint64_t dyn_offset)
{
	elf_dynamic_t d = {0};

	if (info->is_64) {
		const Elf64_Dyn *dyn = (const Elf64_Dyn *)(info->data + dyn_offset);

		for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
			switch (dyn[i].d_tag) {
			/* String/Symbol tables */
			case DT_STRTAB:        d.strtab = dyn[i].d_un.d_ptr; break;
			case DT_STRSZ:         d.strsz = dyn[i].d_un.d_val; break;
			case DT_SYMTAB:        d.symtab = dyn[i].d_un.d_ptr; break;
			case DT_SYMENT:        d.syment = dyn[i].d_un.d_val; break;

			/* Hash tables */
			case DT_HASH:          d.hash = dyn[i].d_un.d_ptr; break;
			case DT_GNU_HASH:      d.gnu_hash = dyn[i].d_un.d_ptr; break;

			/* RELA relocations */
			case DT_RELA:          d.rela = dyn[i].d_un.d_ptr; break;
			case DT_RELASZ:        d.relasz = dyn[i].d_un.d_val; break;
			case DT_RELAENT:       d.relaent = dyn[i].d_un.d_val; break;

			/* REL relocations */
			case DT_REL:           d.rel = dyn[i].d_un.d_ptr; break;
			case DT_RELSZ:         d.relsz = dyn[i].d_un.d_val; break;
			case DT_RELENT:        d.relent = dyn[i].d_un.d_val; break;

			/* PLT relocations */
			case DT_JMPREL:        d.jmprel = dyn[i].d_un.d_ptr; break;
			case DT_PLTRELSZ:      d.pltrelsz = dyn[i].d_un.d_val; break;
			case DT_PLTREL:        d.pltrel = dyn[i].d_un.d_val; break;

			/* RELR relocations */
			case DT_RELR:          d.relr = dyn[i].d_un.d_ptr; break;
			case DT_RELRSZ:        d.relrsz = dyn[i].d_un.d_val; break;
			case DT_RELRENT:       d.relrent = dyn[i].d_un.d_val; break;

			/* Init/Fini */
			case DT_INIT:          d.init = dyn[i].d_un.d_ptr; break;
			case DT_FINI:          d.fini = dyn[i].d_un.d_ptr; break;
			case DT_INIT_ARRAY:    d.init_array = dyn[i].d_un.d_ptr; break;
			case DT_INIT_ARRAYSZ:  d.init_arraysz = dyn[i].d_un.d_val; break;
			case DT_FINI_ARRAY:    d.fini_array = dyn[i].d_un.d_ptr; break;
			case DT_FINI_ARRAYSZ:  d.fini_arraysz = dyn[i].d_un.d_val; break;
			case DT_PREINIT_ARRAY: d.preinit_array = dyn[i].d_un.d_ptr; break;
			case DT_PREINIT_ARRAYSZ: d.preinit_arraysz = dyn[i].d_un.d_val; break;

			/* Versioning */
			case DT_VERSYM:        d.versym = dyn[i].d_un.d_ptr; break;
			case DT_VERNEED:       d.verneed = dyn[i].d_un.d_ptr; break;
			case DT_VERNEEDNUM:    d.verneednum = dyn[i].d_un.d_val; break;
			case DT_VERDEF:        d.verdef = dyn[i].d_un.d_ptr; break;
			case DT_VERDEFNUM:     d.verdefnum = dyn[i].d_un.d_val; break;

			/* GOT/PLT */
			case DT_PLTGOT:        d.pltgot = dyn[i].d_un.d_ptr; break;

			/* Flags */
			case DT_FLAGS:
				d.flags = dyn[i].d_un.d_val;
				if (d.flags & DF_TEXTREL)
					d.has_textrel = true;
				break;
			case DT_FLAGS_1:
				d.flags_1 = dyn[i].d_un.d_val;
				break;
			case DT_TEXTREL:
				d.has_textrel = true;
				break;
			}
		}

		/* Default entry sizes for 64-bit */
		if (!d.relaent) d.relaent = sizeof(Elf64_Rela);
		if (!d.relent)  d.relent = sizeof(Elf64_Rel);
		if (!d.relrent) d.relrent = sizeof(uint64_t);
		if (!d.syment)  d.syment = sizeof(Elf64_Sym);
	} else {
		const Elf32_Dyn *dyn = (const Elf32_Dyn *)(info->data + dyn_offset);

		for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
			switch (dyn[i].d_tag) {
			/* String/Symbol tables */
			case DT_STRTAB:        d.strtab = dyn[i].d_un.d_ptr; break;
			case DT_STRSZ:         d.strsz = dyn[i].d_un.d_val; break;
			case DT_SYMTAB:        d.symtab = dyn[i].d_un.d_ptr; break;
			case DT_SYMENT:        d.syment = dyn[i].d_un.d_val; break;

			/* Hash tables */
			case DT_HASH:          d.hash = dyn[i].d_un.d_ptr; break;
			case DT_GNU_HASH:      d.gnu_hash = dyn[i].d_un.d_ptr; break;

			/* RELA relocations */
			case DT_RELA:          d.rela = dyn[i].d_un.d_ptr; break;
			case DT_RELASZ:        d.relasz = dyn[i].d_un.d_val; break;
			case DT_RELAENT:       d.relaent = dyn[i].d_un.d_val; break;

			/* REL relocations */
			case DT_REL:           d.rel = dyn[i].d_un.d_ptr; break;
			case DT_RELSZ:         d.relsz = dyn[i].d_un.d_val; break;
			case DT_RELENT:        d.relent = dyn[i].d_un.d_val; break;

			/* PLT relocations */
			case DT_JMPREL:        d.jmprel = dyn[i].d_un.d_ptr; break;
			case DT_PLTRELSZ:      d.pltrelsz = dyn[i].d_un.d_val; break;
			case DT_PLTREL:        d.pltrel = dyn[i].d_un.d_val; break;

			/* Init/Fini */
			case DT_INIT:          d.init = dyn[i].d_un.d_ptr; break;
			case DT_FINI:          d.fini = dyn[i].d_un.d_ptr; break;
			case DT_INIT_ARRAY:    d.init_array = dyn[i].d_un.d_ptr; break;
			case DT_INIT_ARRAYSZ:  d.init_arraysz = dyn[i].d_un.d_val; break;
			case DT_FINI_ARRAY:    d.fini_array = dyn[i].d_un.d_ptr; break;
			case DT_FINI_ARRAYSZ:  d.fini_arraysz = dyn[i].d_un.d_val; break;
			case DT_PREINIT_ARRAY: d.preinit_array = dyn[i].d_un.d_ptr; break;
			case DT_PREINIT_ARRAYSZ: d.preinit_arraysz = dyn[i].d_un.d_val; break;

			/* Versioning */
			case DT_VERSYM:        d.versym = dyn[i].d_un.d_ptr; break;
			case DT_VERNEED:       d.verneed = dyn[i].d_un.d_ptr; break;
			case DT_VERNEEDNUM:    d.verneednum = dyn[i].d_un.d_val; break;
			case DT_VERDEF:        d.verdef = dyn[i].d_un.d_ptr; break;
			case DT_VERDEFNUM:     d.verdefnum = dyn[i].d_un.d_val; break;

			/* GOT/PLT */
			case DT_PLTGOT:        d.pltgot = dyn[i].d_un.d_ptr; break;

			/* Flags */
			case DT_FLAGS:
				d.flags = dyn[i].d_un.d_val;
				if (d.flags & DF_TEXTREL)
					d.has_textrel = true;
				break;
			case DT_FLAGS_1:
				d.flags_1 = dyn[i].d_un.d_val;
				break;
			case DT_TEXTREL:
				d.has_textrel = true;
				break;
			}
		}

		/* Default entry sizes for 32-bit */
		if (!d.relaent) d.relaent = sizeof(Elf32_Rela);
		if (!d.relent)  d.relent = sizeof(Elf32_Rel);
		if (!d.relrent) d.relrent = sizeof(uint32_t);
		if (!d.syment)  d.syment = sizeof(Elf32_Sym);
	}

	return d;
}

/* ========================================================================== */
/*                         Relocation target sizes                            */
/* ========================================================================== */

/**
 * @brief Get relocation target size for x86_64.
 */
static size_t reloc_size_64(uint32_t type)
{
	switch (type) {
	/* 64-bit relocations */
	case R_X86_64_64:
	case R_X86_64_GLOB_DAT:
	case R_X86_64_JUMP_SLOT:
	case R_X86_64_RELATIVE:
	case R_X86_64_DTPMOD64:
	case R_X86_64_DTPOFF64:
	case R_X86_64_TPOFF64:
	case R_X86_64_IRELATIVE:
		return 8;

	/* 32-bit relocations */
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

	/* 16-bit relocations */
	case R_X86_64_16:
	case R_X86_64_PC16:
		return 2;

	/* 8-bit relocations */
	case R_X86_64_8:
	case R_X86_64_PC8:
		return 1;

	default:
		return 8;
	}
}

/**
 * @brief Get relocation target size for i386.
 */
static size_t reloc_size_32(uint32_t type)
{
	switch (type) {
	/* 32-bit relocations */
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

	/* 16-bit relocations */
	case R_386_16:
	case R_386_PC16:
		return 2;

	/* 8-bit relocations */
	case R_386_8:
	case R_386_PC8:
		return 1;

	default:
		return 4;
	}
}

/* ========================================================================== */
/*                       Relocation target protection                         */
/* ========================================================================== */

/**
 * @brief Protect RELA relocation targets.
 */
static void protect_rela_targets(elf_protected_list_t *list,
                                 const elf_info_t *info,
                                 uint64_t rela_vaddr,
                                 uint64_t relasz,
                                 uint64_t relaent)
{
	if (!rela_vaddr || !relasz)
		return;

	uint64_t rela_off = elf_vaddr_to_offset(info, rela_vaddr);
	if (!rela_off)
		return;

	size_t count = relasz / relaent;

	if (info->is_64) {
		const Elf64_Rela *rela = (const Elf64_Rela *)(info->data + rela_off);
		for (size_t i = 0; i < count; i++) {
			uint64_t target_off = elf_vaddr_to_offset(info, rela[i].r_offset);
			if (target_off) {
				uint32_t type = ELF64_R_TYPE(rela[i].r_info);
				list_add(list, target_off, reloc_size_64(type));
			}
		}
	} else {
		const Elf32_Rela *rela = (const Elf32_Rela *)(info->data + rela_off);
		for (size_t i = 0; i < count; i++) {
			uint64_t target_off = elf_vaddr_to_offset(info, rela[i].r_offset);
			if (target_off) {
				uint32_t type = ELF32_R_TYPE(rela[i].r_info);
				list_add(list, target_off, reloc_size_32(type));
			}
		}
	}
}

/**
 * @brief Protect REL relocation targets.
 */
static void protect_rel_targets(elf_protected_list_t *list,
                                const elf_info_t *info,
                                uint64_t rel_vaddr,
                                uint64_t relsz,
                                uint64_t relent)
{
	if (!rel_vaddr || !relsz)
		return;

	uint64_t rel_off = elf_vaddr_to_offset(info, rel_vaddr);
	if (!rel_off)
		return;

	size_t count = relsz / relent;

	if (info->is_64) {
		const Elf64_Rel *rel = (const Elf64_Rel *)(info->data + rel_off);
		for (size_t i = 0; i < count; i++) {
			uint64_t target_off = elf_vaddr_to_offset(info, rel[i].r_offset);
			if (target_off) {
				uint32_t type = ELF64_R_TYPE(rel[i].r_info);
				list_add(list, target_off, reloc_size_64(type));
			}
		}
	} else {
		const Elf32_Rel *rel = (const Elf32_Rel *)(info->data + rel_off);
		for (size_t i = 0; i < count; i++) {
			uint64_t target_off = elf_vaddr_to_offset(info, rel[i].r_offset);
			if (target_off) {
				uint32_t type = ELF32_R_TYPE(rel[i].r_info);
				list_add(list, target_off, reloc_size_32(type));
			}
		}
	}
}

/**
 * @brief Protect RELR relocation targets (compact format).
 */
static void protect_relr_targets(elf_protected_list_t *list,
                                 const elf_info_t *info,
                                 uint64_t relr_vaddr,
                                 uint64_t relrsz,
                                 uint64_t relrent)
{
	if (!relr_vaddr || !relrsz)
		return;

	uint64_t relr_off = elf_vaddr_to_offset(info, relr_vaddr);
	if (!relr_off)
		return;

	size_t count = relrsz / relrent;
	uint64_t base = 0;

	if (info->is_64) {
		const uint64_t *relr = (const uint64_t *)(info->data + relr_off);
		for (size_t i = 0; i < count; i++) {
			uint64_t entry = relr[i];
			if ((entry & 1) == 0) {
				/* Direct address */
				uint64_t target_off = elf_vaddr_to_offset(info, entry);
				if (target_off)
					list_add(list, target_off, 8);
				base = entry + 8;
			} else {
				/* Bitmap: each bit represents 8-byte slot */
				uint64_t bitmap = entry >> 1;
				for (int j = 0; bitmap; j++, bitmap >>= 1) {
					if (bitmap & 1) {
						uint64_t target_off = elf_vaddr_to_offset(info, base + j * 8);
						if (target_off)
							list_add(list, target_off, 8);
					}
				}
				base += 63 * 8;
			}
		}
	} else {
		const uint32_t *relr = (const uint32_t *)(info->data + relr_off);
		for (size_t i = 0; i < count; i++) {
			uint32_t entry = relr[i];
			if ((entry & 1) == 0) {
				/* Direct address */
				uint64_t target_off = elf_vaddr_to_offset(info, entry);
				if (target_off)
					list_add(list, target_off, 4);
				base = entry + 4;
			} else {
				/* Bitmap: each bit represents 4-byte slot */
				uint32_t bitmap = entry >> 1;
				for (int j = 0; bitmap; j++, bitmap >>= 1) {
					if (bitmap & 1) {
						uint64_t target_off = elf_vaddr_to_offset(info, base + j * 4);
						if (target_off)
							list_add(list, target_off, 4);
					}
				}
				base += 31 * 4;
			}
		}
	}
}

/* ========================================================================== */
/*                          Versioning protection                             */
/* ========================================================================== */

/**
 * @brief Protect verneed table.
 */
static void protect_verneed(elf_protected_list_t *list,
                            const elf_info_t *info,
                            uint64_t verneed_vaddr,
                            uint64_t verneednum)
{
	if (!verneed_vaddr || !verneednum)
		return;

	uint64_t off = elf_vaddr_to_offset(info, verneed_vaddr);
	if (!off)
		return;

	uint8_t *start = info->data + off;
	uint8_t *end = start;

	if (info->is_64) {
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

	list_add(list, off, end - start);
}

/**
 * @brief Protect verdef table.
 */
static void protect_verdef(elf_protected_list_t *list,
                           const elf_info_t *info,
                           uint64_t verdef_vaddr,
                           uint64_t verdefnum)
{
	if (!verdef_vaddr || !verdefnum)
		return;

	uint64_t off = elf_vaddr_to_offset(info, verdef_vaddr);
	if (!off)
		return;

	uint8_t *start = info->data + off;
	uint8_t *end = start;

	if (info->is_64) {
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

	list_add(list, off, end - start);
}

/* ========================================================================== */
/*                            Public functions                                */
/* ========================================================================== */

bool elf_info_init(uint8_t *elf, size_t size, elf_info_t *info)
{
	if (size < EI_NIDENT)
		return false;

	/* Verify ELF magic */
	if (memcmp(elf, ELFMAG, SELFMAG) != 0)
		return false;

	info->data = elf;
	info->size = size;
	info->is_64 = (elf[EI_CLASS] == ELFCLASS64);

	if (info->is_64) {
		if (size < sizeof(Elf64_Ehdr))
			return false;
		const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf;
		info->phoff = ehdr->e_phoff;
		info->phnum = ehdr->e_phnum;
		info->phentsize = ehdr->e_phentsize;
	} else {
		if (size < sizeof(Elf32_Ehdr))
			return false;
		const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *)elf;
		info->phoff = ehdr->e_phoff;
		info->phnum = ehdr->e_phnum;
		info->phentsize = ehdr->e_phentsize;
	}

	return true;
}

uint64_t elf_vaddr_to_offset(const elf_info_t *info, uint64_t vaddr)
{
	for (int i = 0; i < info->phnum; i++) {
		if (phdr_type(info, i) != PT_LOAD)
			continue;

		uint64_t pv = phdr_vaddr(info, i);
		uint64_t pf = phdr_filesz(info, i);
		uint64_t po = phdr_offset(info, i);

		if (vaddr >= pv && vaddr < pv + pf)
			return vaddr - pv + po;
	}
	return 0;
}

elf_protected_list_t elf_get_protected_ranges(const elf_info_t *info)
{
	elf_protected_list_t list = {0};
	uint64_t dyn_offset = 0;
	size_t ptr_size = info->is_64 ? 8 : 4;

	/*
	 * 1. ELF Header - Required by kernel
	 */
	if (info->is_64)
		list_add(&list, 0, sizeof(Elf64_Ehdr));
	else
		list_add(&list, 0, sizeof(Elf32_Ehdr));

	/*
	 * 2. Program Header Table - Required by kernel/loader
	 */
	size_t phdr_size = info->is_64 ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr);
	list_add(&list, info->phoff, info->phnum * phdr_size);

	/*
	 * 3. Required segments
	 */
	for (int i = 0; i < info->phnum; i++) {
		uint32_t type = phdr_type(info, i);
		uint64_t offset = phdr_offset(info, i);
		uint64_t filesz = phdr_filesz(info, i);

		switch (type) {
		case PT_INTERP:
			/* Dynamic linker path - Required by kernel */
			list_add(&list, offset, filesz);
			break;

		case PT_DYNAMIC:
			/* Dynamic section - Required by ld.so */
			list_add(&list, offset, filesz);
			dyn_offset = offset;
			break;

		case PT_GNU_PROPERTY:
			/* CET/BTI properties - May be required by kernel */
			list_add(&list, offset, filesz);
			break;
		}
	}

	/* Static binary - no more to protect */
	if (!dyn_offset)
		return list;

	/*
	 * 4. Parse PT_DYNAMIC and protect referenced tables
	 */
	elf_dynamic_t d = parse_dynamic(info, dyn_offset);

	/* String table */
	if (d.strtab && d.strsz) {
		uint64_t off = elf_vaddr_to_offset(info, d.strtab);
		if (off)
			list_add(&list, off, d.strsz);
	}

	/* Symbol table (size = strtab - symtab by convention) */
	if (d.symtab && d.strtab && d.strtab > d.symtab) {
		uint64_t off = elf_vaddr_to_offset(info, d.symtab);
		if (off)
			list_add(&list, off, d.strtab - d.symtab);
	}

	/* Calculate nsyms for later use */
	uint64_t nsyms = 0;
	if (d.symtab && d.strtab && d.syment)
		nsyms = (d.strtab - d.symtab) / d.syment;

	/* SYSV hash table */
	if (d.hash) {
		uint64_t off = elf_vaddr_to_offset(info, d.hash);
		if (off) {
			const uint32_t *h = (const uint32_t *)(info->data + off);
			uint32_t nbucket = h[0];
			uint32_t nchain = h[1];
			list_add(&list, off, (2 + nbucket + nchain) * sizeof(uint32_t));
		}
	}

	/* GNU hash table */
	if (d.gnu_hash) {
		uint64_t off = elf_vaddr_to_offset(info, d.gnu_hash);
		if (off) {
			const uint32_t *gh = (const uint32_t *)(info->data + off);
			uint32_t nbuckets = gh[0];
			uint32_t symndx = gh[1];
			uint32_t maskwords = gh[2];

			uint64_t chains_size = 0;
			if (nsyms > symndx)
				chains_size = (nsyms - symndx) * sizeof(uint32_t);

			/*
			 * GNU hash layout:
			 * - Header: 4 * uint32 = 16 bytes
			 * - Bloom filter: maskwords * ptr_size
			 * - Buckets: nbuckets * 4
			 * - Chains: (nsyms - symndx) * 4
			 */
			uint64_t total = 16 + maskwords * ptr_size + nbuckets * 4 + chains_size;
			list_add(&list, off, total);
		}
	}

	/*
	 * 5. Relocation tables
	 */
	if (d.rela && d.relasz) {
		uint64_t off = elf_vaddr_to_offset(info, d.rela);
		if (off)
			list_add(&list, off, d.relasz);
	}

	if (d.rel && d.relsz) {
		uint64_t off = elf_vaddr_to_offset(info, d.rel);
		if (off)
			list_add(&list, off, d.relsz);
	}

	if (d.jmprel && d.pltrelsz) {
		uint64_t off = elf_vaddr_to_offset(info, d.jmprel);
		if (off)
			list_add(&list, off, d.pltrelsz);
	}

	if (d.relr && d.relrsz) {
		uint64_t off = elf_vaddr_to_offset(info, d.relr);
		if (off)
			list_add(&list, off, d.relrsz);
	}

	/*
	 * 6. Relocation targets (r_offset of each relocation)
	 */
	protect_rela_targets(&list, info, d.rela, d.relasz, d.relaent);
	protect_rel_targets(&list, info, d.rel, d.relsz, d.relent);
	protect_relr_targets(&list, info, d.relr, d.relrsz, d.relrent);

	/* PLT relocations can be either RELA or REL */
	if (d.jmprel && d.pltrelsz) {
		if (d.pltrel == DT_RELA)
			protect_rela_targets(&list, info, d.jmprel, d.pltrelsz, d.relaent);
		else
			protect_rel_targets(&list, info, d.jmprel, d.pltrelsz, d.relent);
	}

	/*
	 * 7. Init/Fini functions and arrays
	 */
	if (d.init) {
		uint64_t off = elf_vaddr_to_offset(info, d.init);
		if (off)
			list_add(&list, off, ptr_size);
	}

	if (d.fini) {
		uint64_t off = elf_vaddr_to_offset(info, d.fini);
		if (off)
			list_add(&list, off, ptr_size);
	}

	if (d.init_array && d.init_arraysz) {
		uint64_t off = elf_vaddr_to_offset(info, d.init_array);
		if (off)
			list_add(&list, off, d.init_arraysz);
	}

	if (d.fini_array && d.fini_arraysz) {
		uint64_t off = elf_vaddr_to_offset(info, d.fini_array);
		if (off)
			list_add(&list, off, d.fini_arraysz);
	}

	if (d.preinit_array && d.preinit_arraysz) {
		uint64_t off = elf_vaddr_to_offset(info, d.preinit_array);
		if (off)
			list_add(&list, off, d.preinit_arraysz);
	}

	/*
	 * 8. Symbol versioning tables
	 */
	if (d.versym && nsyms) {
		uint64_t off = elf_vaddr_to_offset(info, d.versym);
		if (off)
			list_add(&list, off, nsyms * sizeof(uint16_t));
	}

	protect_verneed(&list, info, d.verneed, d.verneednum);
	protect_verdef(&list, info, d.verdef, d.verdefnum);

	/*
	 * 9. GOT/PLT
	 */
	if (d.pltgot) {
		uint64_t off = elf_vaddr_to_offset(info, d.pltgot);
		if (off) {
			/* GOT layout: 3 reserved entries + one per PLT relocation */
			size_t got_entries = 3;
			if (d.jmprel && d.pltrelsz) {
				size_t reloc_size;
				if (d.pltrel == DT_RELA)
					reloc_size = info->is_64 ? sizeof(Elf64_Rela) : sizeof(Elf32_Rela);
				else
					reloc_size = info->is_64 ? sizeof(Elf64_Rel) : sizeof(Elf32_Rel);
				got_entries += d.pltrelsz / reloc_size;
			}
			list_add(&list, off, got_entries * ptr_size);
		}
	}

	return list;
}

bool elf_is_protected(const elf_protected_list_t *list, uint64_t offset)
{
	for (size_t i = 0; i < list->count; i++) {
		if (offset >= list->ranges[i].offset &&
		    offset < list->ranges[i].offset + list->ranges[i].size)
			return true;
	}
	return false;
}

bool elf_range_is_protected(const elf_protected_list_t *list,
                            uint64_t offset, uint64_t size)
{
	uint64_t end = offset + size;
	for (size_t i = 0; i < list->count; i++) {
		uint64_t r_start = list->ranges[i].offset;
		uint64_t r_end = r_start + list->ranges[i].size;

		/* Check for overlap */
		if (offset < r_end && end > r_start)
			return true;
	}
	return false;
}

bool elf_has_textrel(const elf_info_t *info)
{
	/* Find PT_DYNAMIC */
	uint64_t dyn_offset = 0;
	for (int i = 0; i < info->phnum; i++) {
		if (phdr_type(info, i) == PT_DYNAMIC) {
			dyn_offset = phdr_offset(info, i);
			break;
		}
	}

	if (!dyn_offset)
		return false;

	elf_dynamic_t d = parse_dynamic(info, dyn_offset);
	return d.has_textrel;
}

void elf_protected_list_free(elf_protected_list_t *list)
{
	free(list->ranges);
	list->ranges = NULL;
	list->count = 0;
	list->cap = 0;
}
