/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   elf_reader64.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Antoine Massias <massias.antoine.pro@gm    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/16 09:46:23 by amassias          #+#    #+#             */
/*   Updated: 2025/12/18 13:21:21 by Antoine Mas      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "int_elf_reader.h"
# include "int_elf_offset.h"

static
uint64_t	_get_eh_entry(
				t_elf_file *s
				);

static
uint64_t	_get_eh_phoff(
				t_elf_file *s
				);

static
uint16_t	_get_eh_phentsize(
				t_elf_file *s
				);

static
uint16_t	_get_eh_phnum(
				t_elf_file *s
				);

static
void		*_get_pht(
				t_elf_file *s
				);

static
void		*_get_ph(
				t_elf_file *s,
				size_t
				);

static
void		_set_eh_phoff(
				t_elf_file *s,
				uint64_t off
				);

static
void		_set_eh_phentsize(
				t_elf_file *s,
				uint16_t entsize
				);

static
void		_set_eh_phnum(
				t_elf_file *s,
				uint16_t num
				);

static
uint64_t	_get_eh_shoff(
				t_elf_file *s
				);

static
uint16_t	_get_eh_shentsize(
				t_elf_file *s
				);

static
uint16_t	_get_eh_shnum(
				t_elf_file *s
				);

static
void		*_get_sht(
				t_elf_file *s
				);

static
void		*_get_sh(
				t_elf_file *s,
				size_t
				);

static
void		_set_eh_entry(
				t_elf_file *s,
				uint64_t entry
				);

static
void		_set_eh_shoff(
				t_elf_file *s,
				uint64_t off
				);

static
void		_set_eh_shentsize(
				t_elf_file *s,
				uint16_t entsize
				);

static
void		_set_eh_shnum(
				t_elf_file *s,
				uint16_t num
				);

static
uint32_t	_get_ph_type(
				t_elf_file *s,
				size_t n
				);

static
uint32_t	_get_ph_flags(
				t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_ph_offset(
				t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_ph_vaddr(
				t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_ph_paddr(
				t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_ph_filesz(
				t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_ph_memsz(
				t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_ph_align(
				t_elf_file *s,
				size_t n
				);

static
void		_set_ph_type(
				t_elf_file *s,
				size_t n,
				uint32_t type
				);

static
void		_set_ph_flags(
				t_elf_file *s,
				size_t n,
				uint32_t flags
				);

static
void		_set_ph_offset(
				t_elf_file *s,
				size_t n,
				uint64_t offset
				);

static
void		_set_ph_vaddr(
				t_elf_file *s,
				size_t n,
				uint64_t vaddr
				);

static
void		_set_ph_paddr(
				t_elf_file *s,
				size_t n,
				uint64_t paddr
				);

static
void		_set_ph_filesz(
				t_elf_file *s,
				size_t n,
				uint64_t filesz
				);

static
void		_set_ph_memsz(
				t_elf_file *s,
				size_t n,
				uint64_t memsz
				);

static
void		_set_ph_align(
				t_elf_file *s,
				size_t n,
				uint64_t align
				);

static
uint32_t	_get_sh_name(
				t_elf_file *s,
				size_t n
				);

static
uint32_t	_get_sh_type(
				t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_sh_flags(
				t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_sh_addr(
				t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_sh_offset(
				t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_sh_size(
				t_elf_file *s,
				size_t n
				);

static
uint32_t	_get_sh_link(
				t_elf_file *s,
				size_t n
				);

static
uint32_t	_get_sh_info(
				t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_sh_addralign(
				t_elf_file *s,
				size_t n
				);

static
uint64_t	_get_sh_entsize(
				t_elf_file *s,
				size_t n
				);

static
void		_set_sh_name(
				t_elf_file *s,
				size_t n,
				uint32_t name
				);

static
void		_set_sh_type(
				t_elf_file *s,
				size_t n,
				uint32_t type
				);

static
void		_set_sh_flags(
				t_elf_file *s,
				size_t n,
				uint64_t flags
				);

static
void		_set_sh_addr(
				t_elf_file *s,
				size_t n,
				uint64_t addr
				);

static
void		_set_sh_offset(
				t_elf_file *s,
				size_t n,
				uint64_t offset
				);

static
void		_set_sh_size(
				t_elf_file *s,
				size_t n,
				uint64_t size
				);

static
void		_set_sh_link(
				t_elf_file *s,
				size_t n,
				uint32_t link
				);

static
void		_set_sh_info(
				t_elf_file *s,
				size_t n,
				uint32_t info
				);

static
void		_set_sh_addralign(
				t_elf_file *s,
				size_t n,
				uint64_t addralign
				);

static
void		_set_sh_entsize(
				t_elf_file *s,
				size_t n,
				uint64_t entsize
				);

void	int_elf_load_64bit_handlers(
			t_elf_file *s
			)
{
	s->hdl = (t_elf_handler){
		.eh = {
			.get = {
				.entry = _get_eh_entry,
				.phoff = _get_eh_phoff,
				.phentsize = _get_eh_phentsize,
				.phnum = _get_eh_phnum,
				.shoff = _get_eh_shoff,
				.shentsize = _get_eh_shentsize,
				.shnum = _get_eh_shnum,
				.pht = _get_pht,
				.ph = _get_ph,
				.sht = _get_sht,
				.sh = _get_sh,
			},
			.set = {
				.entry = _set_eh_entry,
				.phoff = _set_eh_phoff,
				.phentsize = _set_eh_phentsize,
				.phnum = _set_eh_phnum,
				.shoff = _set_eh_shoff,
				.shentsize = _set_eh_shentsize,
				.shnum = _set_eh_shnum,
			},
		},
		.ph = {
			.get = {
				.type = _get_ph_type,
				.flags = _get_ph_flags,
				.offset = _get_ph_offset,
				.vaddr = _get_ph_vaddr,
				.paddr = _get_ph_paddr,
				.filesz = _get_ph_filesz,
				.memsz = _get_ph_memsz,
				.align = _get_ph_align,
			},
			.set = {
				.type = _set_ph_type,
				.flags = _set_ph_flags,
				.offset = _set_ph_offset,
				.vaddr = _set_ph_vaddr,
				.paddr = _set_ph_paddr,
				.filesz = _set_ph_filesz,
				.memsz = _set_ph_memsz,
				.align = _set_ph_align,
			},
		},
		.sh = {
			.get = {
				.name = _get_sh_name,
				.type = _get_sh_type,
				.flags = _get_sh_flags,
				.addr = _get_sh_addr,
				.offset = _get_sh_offset,
				.size = _get_sh_size,
				.link = _get_sh_link,
				.info = _get_sh_info,
				.addralign = _get_sh_addralign,
				.entsize = _get_sh_entsize,
			},
			.set = {
				.name = _set_sh_name,
				.type = _set_sh_type,
				.flags = _set_sh_flags,
				.addr = _set_sh_addr,
				.offset = _set_sh_offset,
				.size = _set_sh_size,
				.link = _set_sh_link,
				.info = _set_sh_info,
				.addralign = _set_sh_addralign,
				.entsize = _set_sh_entsize,
			},
		},
	};
}

static
uint64_t	_get_eh_entry(
				t_elf_file *s
				)
{
	return (s->io.read64(s->data, ELF64_OFF__EH_ENTRY));
}

static
uint64_t	_get_eh_phoff(
				t_elf_file *s
				)
{
	return (s->io.read64(s->data, ELF64_OFF__EH_PHOFF));
}

static
uint16_t	_get_eh_phentsize(
				t_elf_file *s
				)
{
	return (s->io.read16(s->data, ELF64_OFF__EH_PHENTSIZE));
}

static
uint16_t	_get_eh_phnum(
				t_elf_file *s
				)
{
	return (s->io.read16(s->data, ELF64_OFF__EH_PHNUM));
}

static
void		*_get_pht(
				t_elf_file *s
				)
{
	const uint8_t	*base = s->data;
	const uint64_t	off = _get_eh_phoff(s);

	return ((void *)&base[off]);
}

static
void		*_get_ph(
				t_elf_file *s,
				size_t n
				)
{
	const uint8_t	*base = s->data;
	const uint64_t	off = _get_eh_phoff(s);
	const uint32_t	entsize = _get_eh_phentsize(s);

	return ((void *)&base[off + n * entsize]);
}

static
void		_set_eh_entry(
				t_elf_file *s,
				uint64_t entry
				)
{
	s->io.write64(s->data, ELF64_OFF__EH_ENTRY, entry);
}

static
void		_set_eh_phoff(
				t_elf_file *s,
				uint64_t off
				)
{
	s->io.write64(s->data, ELF64_OFF__EH_PHOFF, off);
}

static
void		_set_eh_phentsize(
				t_elf_file *s,
				uint16_t entsize
				)
{
	s->io.write16(s->data, ELF64_OFF__EH_PHENTSIZE, entsize);
}

static
void		_set_eh_phnum(
				t_elf_file *s,
				uint16_t num
				)
{
	s->io.write16(s->data, ELF64_OFF__EH_PHNUM, num);
}

static
uint64_t	_get_eh_shoff(
				t_elf_file *s
				)
{
	return (s->io.read64(s->data, ELF64_OFF__EH_SHOFF));
}

static
uint16_t	_get_eh_shentsize(
				t_elf_file *s
				)
{
	return (s->io.read16(s->data, ELF64_OFF__EH_SHENTSIZE));
}

static
uint16_t	_get_eh_shnum(
				t_elf_file *s
				)
{
	return (s->io.read16(s->data, ELF64_OFF__EH_SHNUM));
}

static
void		*_get_sht(
				t_elf_file *s
				)
{
	const uint8_t	*base = s->data;
	const uint64_t	off = _get_eh_shoff(s);

	return ((void *)&base[off]);
}

static
void		*_get_sh(
				t_elf_file *s,
				size_t n
				)
{
	const uint8_t	*base = s->data;
	const uint64_t	off = _get_eh_shoff(s);
	const uint32_t	entsize = _get_eh_shentsize(s);

	return ((void *)&base[off + n * entsize]);
}

static
void		_set_eh_shoff(
				t_elf_file *s,
				uint64_t off
				)
{
	s->io.write64(s->data, ELF64_OFF__EH_SHOFF, off);
}

static
void		_set_eh_shentsize(
				t_elf_file *s,
				uint16_t entsize
				)
{
	s->io.write16(s->data, ELF64_OFF__EH_SHENTSIZE, entsize);
}

static
void		_set_eh_shnum(
				t_elf_file *s,
				uint16_t num
				)
{
	s->io.write16(s->data, ELF64_OFF__EH_SHNUM, num);
}

static
uint32_t	_get_ph_type(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read32(page, ELF64_OFF__PH_TYPE));
}

static
uint32_t	_get_ph_flags(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read32(page, ELF64_OFF__PH_FLAGS));
}

static
uint64_t	_get_ph_offset(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read64(page, ELF64_OFF__PH_OFFSET));
}

static
uint64_t	_get_ph_vaddr(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read64(page, ELF64_OFF__PH_VADDR));
}

static
uint64_t	_get_ph_paddr(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read64(page, ELF64_OFF__PH_PADDR));
}

static
uint64_t	_get_ph_filesz(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read64(page, ELF64_OFF__PH_FILESZ));
}

static
uint64_t	_get_ph_memsz(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read64(page, ELF64_OFF__PH_MEMSZ));
}

static
uint64_t	_get_ph_align(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_ph(s, n);

	return (s->io.read64(page, ELF64_OFF__PH_ALIGN));
}

static
void		_set_ph_type(
				t_elf_file *s,
				size_t n,
				uint32_t type
				)
{
	void	*page = _get_ph(s, n);

	s->io.write32(page, ELF64_OFF__PH_TYPE, type);
}

static
void		_set_ph_flags(
				t_elf_file *s,
				size_t n,
				uint32_t flags
				)
{
	void	*page = _get_ph(s, n);

	s->io.write32(page, ELF64_OFF__PH_FLAGS, flags);
}

static
void		_set_ph_offset(
				t_elf_file *s,
				size_t n,
				uint64_t offset
				)
{
	void	*page = _get_ph(s, n);

	s->io.write64(page, ELF64_OFF__PH_OFFSET, offset);
}

static
void		_set_ph_vaddr(
				t_elf_file *s,
				size_t n,
				uint64_t vaddr
				)
{
	void	*page = _get_ph(s, n);

	s->io.write64(page, ELF64_OFF__PH_VADDR, vaddr);
}

static
void		_set_ph_paddr(
				t_elf_file *s,
				size_t n,
				uint64_t paddr
				)
{
	void	*page = _get_ph(s, n);

	s->io.write64(page, ELF64_OFF__PH_PADDR, paddr);
}

static
void		_set_ph_filesz(
				t_elf_file *s,
				size_t n,
				uint64_t filesz
				)
{
	void	*page = _get_ph(s, n);

	s->io.write64(page, ELF64_OFF__PH_FILESZ, filesz);
}

static
void		_set_ph_memsz(
				t_elf_file *s,
				size_t n,
				uint64_t memsz
				)
{
	void	*page = _get_ph(s, n);

	s->io.write64(page, ELF64_OFF__PH_MEMSZ, memsz);
}

static
void		_set_ph_align(
				t_elf_file *s,
				size_t n,
				uint64_t align
				)
{
	void	*page = _get_ph(s, n);

	s->io.write64(page, ELF64_OFF__PH_ALIGN, align);
}

static
uint32_t	_get_sh_name(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read32(page, ELF64_OFF__SH_NAME));
}

static
uint32_t	_get_sh_type(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read32(page, ELF64_OFF__SH_TYPE));
}

static
uint64_t	_get_sh_flags(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read64(page, ELF64_OFF__SH_FLAGS));
}

static
uint64_t	_get_sh_addr(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read64(page, ELF64_OFF__SH_ADDR));
}

static
uint64_t	_get_sh_offset(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read64(page, ELF64_OFF__SH_OFFSET));
}

static
uint64_t	_get_sh_size(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read64(page, ELF64_OFF__SH_SIZE));
}

static
uint32_t	_get_sh_link(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read32(page, ELF64_OFF__SH_LINK));
}

static
uint32_t	_get_sh_info(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read32(page, ELF64_OFF__SH_INFO));
}

static
uint64_t	_get_sh_addralign(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read64(page, ELF64_OFF__SH_ADDRALIGN));
}

static
uint64_t	_get_sh_entsize(
				t_elf_file *s,
				size_t n
				)
{
	void	*page = _get_sh(s, n);

	return (s->io.read64(page, ELF64_OFF__SH_ENTSIZE));
}

static
void		_set_sh_name(
				t_elf_file *s,
				size_t n,
				uint32_t name
				)
{
	void	*page = _get_sh(s, n);

	s->io.write32(page, ELF64_OFF__SH_NAME, name);
}

static
void		_set_sh_type(
				t_elf_file *s,
				size_t n,
				uint32_t type
				)
{
	void	*page = _get_sh(s, n);

	s->io.write32(page, ELF64_OFF__SH_TYPE, type);
}

static
void		_set_sh_flags(
				t_elf_file *s,
				size_t n,
				uint64_t flags
				)
{
	void	*page = _get_sh(s, n);

	s->io.write64(page, ELF64_OFF__SH_FLAGS, flags);
}

static
void		_set_sh_addr(
				t_elf_file *s,
				size_t n,
				uint64_t addr
				)
{
	void	*page = _get_sh(s, n);

	s->io.write64(page, ELF64_OFF__SH_ADDR, addr);
}

static
void		_set_sh_offset(
				t_elf_file *s,
				size_t n,
				uint64_t offset
				)
{
	void	*page = _get_sh(s, n);

	s->io.write64(page, ELF64_OFF__SH_OFFSET, offset);
}

static
void		_set_sh_size(
				t_elf_file *s,
				size_t n,
				uint64_t size
				)
{
	void	*page = _get_sh(s, n);

	s->io.write64(page, ELF64_OFF__SH_SIZE, size);
}

static
void		_set_sh_link(
				t_elf_file *s,
				size_t n,
				uint32_t link
				)
{
	void	*page = _get_sh(s, n);

	s->io.write32(page, ELF64_OFF__SH_LINK, link);
}

static
void		_set_sh_info(
				t_elf_file *s,
				size_t n,
				uint32_t info
				)
{
	void	*page = _get_sh(s, n);

	s->io.write32(page, ELF64_OFF__SH_INFO, info);
}

static
void		_set_sh_addralign(
				t_elf_file *s,
				size_t n,
				uint64_t addralign
				)
{
	void	*page = _get_sh(s, n);

	s->io.write64(page, ELF64_OFF__SH_ADDRALIGN, addralign);
}

static
void		_set_sh_entsize(
				t_elf_file *s,
				size_t n,
				uint64_t entsize
				)
{
	void	*page = _get_sh(s, n);

	s->io.write64(page, ELF64_OFF__SH_ENTSIZE, entsize);
}
