/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   elf_reader32.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Antoine Massias <massias.antoine.pro@gm    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/16 09:46:23 by amassias          #+#    #+#             */
/*   Updated: 2025/12/18 11:07:13 by Antoine Mas      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "int_elf_reader.h"
# include "int_elf_offset.h"

static
uint64_t	_get_eh_entry(void);

static
uint64_t	_get_eh_phoff(void);

static
uint16_t	_get_eh_phentsize(void);

static
uint16_t	_get_eh_phnum(void);

static
void		*_get_pht(void);

static
void		*_get_ph(
				size_t
				);

static
void		_set_eh_entry(
				uint64_t entry
				);

static
void		_set_eh_phoff(
				uint64_t off
				);

static
void		_set_eh_phentsize(
				uint16_t entsize
				);

static
void		_set_eh_phnum(
				uint16_t num
				);

static
uint64_t	_get_eh_shoff(void);

static
uint16_t	_get_eh_shentsize(void);

static
uint16_t	_get_eh_shnum(void);

static
void		*_get_sht(void);

static
void		*_get_sh(
				size_t
				);

static
void		_set_eh_shoff(
				uint64_t off
				);

static
void		_set_eh_shentsize(
				uint16_t entsize
				);

static
void		_set_eh_shnum(
				uint16_t num
				);

static
uint32_t	_get_ph_type(
				size_t n
				);

static
uint32_t	_get_ph_flags(
				size_t n
				);

static
uint64_t	_get_ph_offset(
				size_t n
				);

static
uint64_t	_get_ph_vaddr(
				size_t n
				);

static
uint64_t	_get_ph_paddr(
				size_t n
				);

static
uint64_t	_get_ph_filesz(
				size_t n
				);

static
uint64_t	_get_ph_memsz(
				size_t n
				);

static
uint64_t	_get_ph_align(
				size_t n
				);

static
void		_set_ph_type(
				size_t n,
				uint32_t type
				);

static
void		_set_ph_flags(
				size_t n,
				uint32_t flags
				);

static
void		_set_ph_offset(
				size_t n,
				uint64_t offset
				);

static
void		_set_ph_vaddr(
				size_t n,
				uint64_t vaddr
				);

static
void		_set_ph_paddr(
				size_t n,
				uint64_t paddr
				);

static
void		_set_ph_filesz(
				size_t n,
				uint64_t filesz
				);

static
void		_set_ph_memsz(
				size_t n,
				uint64_t memsz
				);

static
void		_set_ph_align(
				size_t n,
				uint64_t align
				);

static
uint32_t	_get_sh_name(
				size_t n
				);

static
uint32_t	_get_sh_type(
				size_t n
				);

static
uint64_t	_get_sh_flags(
				size_t n
				);

static
uint64_t	_get_sh_addr(
				size_t n
				);

static
uint64_t	_get_sh_offset(
				size_t n
				);

static
uint64_t	_get_sh_size(
				size_t n
				);

static
uint32_t	_get_sh_link(
				size_t n
				);

static
uint32_t	_get_sh_info(
				size_t n
				);

static
uint64_t	_get_sh_addralign(
				size_t n
				);

static
uint64_t	_get_sh_entsize(
				size_t n
				);

static
void		_set_sh_name(
				size_t n,
				uint32_t name
				);

static
void		_set_sh_type(
				size_t n,
				uint32_t type
				);

static
void		_set_sh_flags(
				size_t n,
				uint64_t flags
				);

static
void		_set_sh_addr(
				size_t n,
				uint64_t addr
				);

static
void		_set_sh_offset(
				size_t n,
				uint64_t offset
				);

static
void		_set_sh_size(
				size_t n,
				uint64_t size
				);

static
void		_set_sh_link(
				size_t n,
				uint32_t link
				);

static
void		_set_sh_info(
				size_t n,
				uint32_t info
				);

static
void		_set_sh_addralign(
				size_t n,
				uint64_t addralign
				);

static
void		_set_sh_entsize(
				size_t n,
				uint64_t entsize
				);

void	int_elf_load_32bit_handlers(void)
{
	elf_eh_get_entry = _get_eh_entry;
	elf_eh_get_phoff = _get_eh_phoff;
	elf_eh_get_phentsize = _get_eh_phentsize;
	elf_eh_get_phnum = _get_eh_phnum;
	elf_eh_get_pht = _get_pht;
	elf_eh_get_ph = _get_ph;
	elf_eh_set_entry = _set_eh_entry;
	elf_eh_set_phoff = _set_eh_phoff;
	elf_eh_set_phentsize = _set_eh_phentsize;
	elf_eh_set_phnum = _set_eh_phnum;
	elf_eh_get_shoff = _get_eh_shoff;
	elf_eh_get_shentsize = _get_eh_shentsize;
	elf_eh_get_shnum = _get_eh_shnum;
	elf_eh_get_sht = _get_sht;
	elf_eh_get_sh = _get_sh;
	elf_eh_set_shoff = _set_eh_shoff;
	elf_eh_set_shentsize = _set_eh_shentsize;
	elf_eh_set_shnum = _set_eh_shnum;
	elf_ph_get_type = _get_ph_type;
	elf_ph_get_flags = _get_ph_flags;
	elf_ph_get_offset = _get_ph_offset;
	elf_ph_get_vaddr = _get_ph_vaddr;
	elf_ph_get_paddr = _get_ph_paddr;
	elf_ph_get_filesz = _get_ph_filesz;
	elf_ph_get_memsz = _get_ph_memsz;
	elf_ph_get_align = _get_ph_align;
	elf_ph_set_type = _set_ph_type;
	elf_ph_set_flags = _set_ph_flags;
	elf_ph_set_offset = _set_ph_offset;
	elf_ph_set_vaddr = _set_ph_vaddr;
	elf_ph_set_paddr = _set_ph_paddr;
	elf_ph_set_filesz = _set_ph_filesz;
	elf_ph_set_memsz = _set_ph_memsz;
	elf_ph_set_align = _set_ph_align;
	elf_sh_get_name = _get_sh_name;
	elf_sh_get_type = _get_sh_type;
	elf_sh_get_flags = _get_sh_flags;
	elf_sh_get_addr = _get_sh_addr;
	elf_sh_get_offset = _get_sh_offset;
	elf_sh_get_size = _get_sh_size;
	elf_sh_get_link = _get_sh_link;
	elf_sh_get_info = _get_sh_info;
	elf_sh_get_addralign = _get_sh_addralign;
	elf_sh_get_entsize = _get_sh_entsize;
	elf_sh_set_name = _set_sh_name;
	elf_sh_set_type = _set_sh_type;
	elf_sh_set_flags = _set_sh_flags;
	elf_sh_set_addr = _set_sh_addr;
	elf_sh_set_offset = _set_sh_offset;
	elf_sh_set_size = _set_sh_size;
	elf_sh_set_link = _set_sh_link;
	elf_sh_set_info = _set_sh_info;
	elf_sh_set_addralign = _set_sh_addralign;
	elf_sh_set_entsize = _set_sh_entsize;
}

static
uint64_t	_get_eh_entry(void)
{
	return (read32(elf_handle.data, ELF32_OFF__EH_ENTRY));
}

static
uint64_t	_get_eh_phoff(void)
{
	return (read32(elf_handle.data, ELF32_OFF__EH_PHOFF));
}

static
uint16_t	_get_eh_phentsize(void)
{
	return (read16(elf_handle.data, ELF32_OFF__EH_PHENTSIZE));
}

static
uint16_t	_get_eh_phnum(void)
{
	return (read16(elf_handle.data, ELF32_OFF__EH_PHNUM));
}

static
void		*_get_pht(void)
{
	const uint8_t	*base = elf_handle.data;
	const uint64_t	off = _get_eh_phoff();

	return ((void *)&base[off]);
}

static
void		*_get_ph(
				size_t n
				)
{
	const uint8_t	*base = elf_handle.data;
	const uint64_t	off = _get_eh_phoff();
	const uint32_t	entsize = _get_eh_phentsize();

	return ((void *)&base[off + n * entsize]);
}

static
void		_set_eh_entry(
				uint64_t entry
				)
{
	write32(elf_handle.data, ELF32_OFF__EH_ENTRY, entry);
}

static
void		_set_eh_phoff(
				uint64_t off
				)
{
	write32(elf_handle.data, ELF32_OFF__EH_PHOFF, off);
}

static
void		_set_eh_phentsize(
				uint16_t entsize
				)
{
	write16(elf_handle.data, ELF32_OFF__EH_PHENTSIZE, entsize);
}

static
void		_set_eh_phnum(
				uint16_t num
				)
{
	write16(elf_handle.data, ELF32_OFF__EH_PHNUM, num);
}

static
uint64_t	_get_eh_shoff(void)
{
	return (read32(elf_handle.data, ELF32_OFF__EH_SHOFF));
}

static
uint16_t	_get_eh_shentsize(void)
{
	return (read16(elf_handle.data, ELF32_OFF__EH_SHENTSIZE));
}

static
uint16_t	_get_eh_shnum(void)
{
	return (read16(elf_handle.data, ELF32_OFF__EH_SHNUM));
}

static
void		*_get_sht(void)
{
	const uint8_t	*base = elf_handle.data;
	const uint64_t	off = _get_eh_shoff();

	return ((void *)&base[off]);
}

static
void		*_get_sh(
				size_t n
				)
{
	const uint8_t	*base = elf_handle.data;
	const uint64_t	off = _get_eh_shoff();
	const uint32_t	entsize = _get_eh_shentsize();

	return ((void *)&base[off + n * entsize]);
}

static
void		_set_eh_shoff(
				uint64_t off
				)
{
	write32(elf_handle.data, ELF32_OFF__EH_SHOFF, off);
}

static
void		_set_eh_shentsize(
				uint16_t entsize
				)
{
	write16(elf_handle.data, ELF32_OFF__EH_SHENTSIZE, entsize);
}

static
void		_set_eh_shnum(
				uint16_t num
				)
{
	write16(elf_handle.data, ELF32_OFF__EH_SHNUM, num);
}

static
uint32_t	_get_ph_type(
				size_t n
				)
{
	void	*page = _get_ph(n);

	return (read32(page, ELF32_OFF__PH_TYPE));
}

static
uint32_t	_get_ph_flags(
				size_t n
				)
{
	void	*page = _get_ph(n);

	return (read32(page, ELF32_OFF__PH_FLAGS));
}

static
uint64_t	_get_ph_offset(
				size_t n
				)
{
	void	*page = _get_ph(n);

	return (read32(page, ELF32_OFF__PH_OFFSET));
}

static
uint64_t	_get_ph_vaddr(
				size_t n
				)
{
	void	*page = _get_ph(n);

	return (read32(page, ELF32_OFF__PH_VADDR));
}

static
uint64_t	_get_ph_paddr(
				size_t n
				)
{
	void	*page = _get_ph(n);

	return (read32(page, ELF32_OFF__PH_PADDR));
}

static
uint64_t	_get_ph_filesz(
				size_t n
				)
{
	void	*page = _get_ph(n);

	return (read32(page, ELF32_OFF__PH_FILESZ));
}

static
uint64_t	_get_ph_memsz(
				size_t n
				)
{
	void	*page = _get_ph(n);

	return (read32(page, ELF32_OFF__PH_MEMSZ));
}

static
uint64_t	_get_ph_align(
				size_t n
				)
{
	void	*page = _get_ph(n);

	return (read32(page, ELF32_OFF__PH_ALIGN));
}

static
void		_set_ph_type(
				size_t n,
				uint32_t type
				)
{
	void	*page = _get_ph(n);

	write32(page, ELF32_OFF__PH_TYPE, type);
}

static
void		_set_ph_flags(
				size_t n,
				uint32_t flags
				)
{
	void	*page = _get_ph(n);

	write32(page, ELF32_OFF__PH_FLAGS, flags);
}

static
void		_set_ph_offset(
				size_t n,
				uint64_t offset
				)
{
	void	*page = _get_ph(n);

	write32(page, ELF32_OFF__PH_OFFSET, offset);
}

static
void		_set_ph_vaddr(
				size_t n,
				uint64_t vaddr
				)
{
	void	*page = _get_ph(n);

	write32(page, ELF32_OFF__PH_VADDR, vaddr);
}

static
void		_set_ph_paddr(
				size_t n,
				uint64_t paddr
				)
{
	void	*page = _get_ph(n);

	write32(page, ELF32_OFF__PH_PADDR, paddr);
}

static
void		_set_ph_filesz(
				size_t n,
				uint64_t filesz
				)
{
	void	*page = _get_ph(n);

	write32(page, ELF32_OFF__PH_FILESZ, filesz);
}

static
void		_set_ph_memsz(
				size_t n,
				uint64_t memsz
				)
{
	void	*page = _get_ph(n);

	write32(page, ELF32_OFF__PH_MEMSZ, memsz);
}

static
void		_set_ph_align(
				size_t n,
				uint64_t align
				)
{
	void	*page = _get_ph(n);

	write32(page, ELF32_OFF__PH_ALIGN, align);
}

static
uint32_t	_get_sh_name(
				size_t n
				)
{
	void	*page = _get_sh(n);

	return (read32(page, ELF32_OFF__SH_NAME));
}

static
uint32_t	_get_sh_type(
				size_t n
				)
{
	void	*page = _get_sh(n);

	return (read32(page, ELF32_OFF__SH_TYPE));
}

static
uint64_t	_get_sh_flags(
				size_t n
				)
{
	void	*page = _get_sh(n);

	return (read32(page, ELF32_OFF__SH_FLAGS));
}

static
uint64_t	_get_sh_addr(
				size_t n
				)
{
	void	*page = _get_sh(n);

	return (read32(page, ELF32_OFF__SH_ADDR));
}

static
uint64_t	_get_sh_offset(
				size_t n
				)
{
	void	*page = _get_sh(n);

	return (read32(page, ELF32_OFF__SH_OFFSET));
}

static
uint64_t	_get_sh_size(
				size_t n
				)
{
	void	*page = _get_sh(n);

	return (read32(page, ELF32_OFF__SH_SIZE));
}

static
uint32_t	_get_sh_link(
				size_t n
				)
{
	void	*page = _get_sh(n);

	return (read32(page, ELF32_OFF__SH_LINK));
}

static
uint32_t	_get_sh_info(
				size_t n
				)
{
	void	*page = _get_sh(n);

	return (read32(page, ELF32_OFF__SH_INFO));
}

static
uint64_t	_get_sh_addralign(
				size_t n
				)
{
	void	*page = _get_sh(n);

	return (read32(page, ELF32_OFF__SH_ADDRALIGN));
}

static
uint64_t	_get_sh_entsize(
				size_t n
				)
{
	void	*page = _get_sh(n);

	return (read32(page, ELF32_OFF__SH_ENTSIZE));
}

static
void		_set_sh_name(
				size_t n,
				uint32_t name
				)
{
	void	*page = _get_sh(n);

	write32(page, ELF32_OFF__SH_NAME, name);
}

static
void		_set_sh_type(
				size_t n,
				uint32_t type
				)
{
	void	*page = _get_sh(n);

	write32(page, ELF32_OFF__SH_TYPE, type);
}

static
void		_set_sh_flags(
				size_t n,
				uint64_t flags
				)
{
	void	*page = _get_sh(n);

	write32(page, ELF32_OFF__SH_FLAGS, flags);
}

static
void		_set_sh_addr(
				size_t n,
				uint64_t addr
				)
{
	void	*page = _get_sh(n);

	write32(page, ELF32_OFF__SH_ADDR, addr);
}

static
void		_set_sh_offset(
				size_t n,
				uint64_t offset
				)
{
	void	*page = _get_sh(n);

	write32(page, ELF32_OFF__SH_OFFSET, offset);
}

static
void		_set_sh_size(
				size_t n,
				uint64_t size
				)
{
	void	*page = _get_sh(n);

	write32(page, ELF32_OFF__SH_SIZE, size);
}

static
void		_set_sh_link(
				size_t n,
				uint32_t link
				)
{
	void	*page = _get_sh(n);

	write32(page, ELF32_OFF__SH_LINK, link);
}

static
void		_set_sh_info(
				size_t n,
				uint32_t info
				)
{
	void	*page = _get_sh(n);

	write32(page, ELF32_OFF__SH_INFO, info);
}

static
void		_set_sh_addralign(
				size_t n,
				uint64_t addralign
				)
{
	void	*page = _get_sh(n);

	write32(page, ELF32_OFF__SH_ADDRALIGN, addralign);
}

static
void		_set_sh_entsize(
				size_t n,
				uint64_t entsize
				)
{
	void	*page = _get_sh(n);

	write32(page, ELF32_OFF__SH_ENTSIZE, entsize);
}
