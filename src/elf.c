/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   elf.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Antoine Massias <massias.antoine.pro@gm    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/15 14:18:35 by amassias          #+#    #+#             */
/*   Updated: 2025/12/17 18:07:50 by Antoine Mas      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#define _GNU_SOURCE

#include "int_elf_reader.h"
#include "utils.h"

#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

#include <stdio.h>
#include <errno.h>

uint64_t	(*elf_eh_get_phoff)(void);
uint16_t	(*elf_eh_get_phentsize)(void);
uint16_t	(*elf_eh_get_phnum)(void);
void		*(*elf_eh_get_pht)();
void		*(*elf_eh_get_ph)(size_t);
void		(*elf_eh_set_phoff)(uint64_t);
void		(*elf_eh_set_phentsize)(uint16_t);
void		(*elf_eh_set_phnum)(uint16_t);
uint64_t	(*elf_eh_get_shoff)(void);
uint16_t	(*elf_eh_get_shentsize)(void);
uint16_t	(*elf_eh_get_shnum)(void);
void		*(*elf_eh_get_sht)();
void		*(*elf_eh_get_sh)(size_t);
void		(*elf_eh_set_shoff)(uint64_t);
void		(*elf_eh_set_shentsize)(uint16_t);
void		(*elf_eh_set_shnum)(uint16_t);
uint32_t	(*elf_ph_get_type)(size_t);
uint32_t	(*elf_ph_get_flags)(size_t);
uint64_t	(*elf_ph_get_offset)(size_t);
uint64_t	(*elf_ph_get_vaddr)(size_t);
uint64_t	(*elf_ph_get_paddr)(size_t);
uint64_t	(*elf_ph_get_filesz)(size_t);
uint64_t	(*elf_ph_get_memsz)(size_t);
uint64_t	(*elf_ph_get_align)(size_t);
void		(*elf_ph_set_type)(size_t, uint32_t);
void		(*elf_ph_set_flags)(size_t, uint32_t);
void		(*elf_ph_set_offset)(size_t, uint64_t);
void		(*elf_ph_set_vaddr)(size_t, uint64_t);
void		(*elf_ph_set_paddr)(size_t, uint64_t);
void		(*elf_ph_set_filesz)(size_t, uint64_t);
void		(*elf_ph_set_memsz)(size_t, uint64_t);
void		(*elf_ph_set_align)(size_t, uint64_t);
uint32_t	(*elf_sh_get_name)(size_t);
uint32_t	(*elf_sh_get_type)(size_t);
uint64_t	(*elf_sh_get_flags)(size_t);
uint64_t	(*elf_sh_get_addr)(size_t);
uint64_t	(*elf_sh_get_offset)(size_t);
uint64_t	(*elf_sh_get_size)(size_t);
uint32_t	(*elf_sh_get_link)(size_t);
uint32_t	(*elf_sh_get_info)(size_t);
uint64_t	(*elf_sh_get_addralign)(size_t);
uint64_t	(*elf_sh_get_entsize)(size_t);
void		(*elf_sh_set_name)(size_t, uint32_t);
void		(*elf_sh_set_type)(size_t, uint32_t);
void		(*elf_sh_set_flags)(size_t, uint64_t);
void		(*elf_sh_set_addr)(size_t, uint64_t);
void		(*elf_sh_set_offset)(size_t, uint64_t);
void		(*elf_sh_set_size)(size_t, uint64_t);
void		(*elf_sh_set_link)(size_t, uint32_t);
void		(*elf_sh_set_info)(size_t, uint32_t);
void		(*elf_sh_set_addralign)(size_t, uint64_t);
void		(*elf_sh_set_entsize)(size_t, uint64_t);

t_elf_file	elf_handle;

static
int			_get_size(
				int fd,
				size_t *size
				);

static
int			_validate_and_load(void);

static
size_t		_get_next_available_vaddr(void);

static
size_t		_get_phdr_index(void);

int			elf_manager_load(
				const char *path
				)
{
	elf_handle.fd = open(path, O_RDWR);
	if (elf_handle.fd < 0)
	{
		perror("open");
		return (EXIT_FAILURE);
	}
	if (_get_size(elf_handle.fd, &elf_handle.size))
	{
		close(elf_handle.fd);
		return (EXIT_FAILURE);
	}
	elf_handle.data = mmap(NULL,
		elf_handle.size,
		PROT_READ | PROT_WRITE,
		MAP_SHARED,
		elf_handle.fd,
		0
	);
	if (elf_handle.data == nullptr)
	{
		perror("mmap");
		close(elf_handle.fd);
		return (EXIT_FAILURE);
	}
	if (_validate_and_load())
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}

int		elf_manager_move_pht_and_emplace_entries(
			size_t n
			)
{
	const size_t	num = elf_eh_get_phnum();
	const size_t	entsize = elf_eh_get_phentsize();
	const size_t	pht_pos = ALIGN_ON(elf_handle.size, 8);
	const size_t	pht_new_size = entsize * (num + n + 1);
	const size_t	phdr_index = _get_phdr_index();
	size_t			pht_vaddr;
	void			*new_data;

	if (ftruncate64(elf_handle.fd, pht_pos + pht_new_size))
	{
		perror("ftruncate64");
		return (EXIT_FAILURE);
	}

	new_data = mremap(elf_handle.data, elf_handle.size, pht_pos + pht_new_size, MREMAP_MAYMOVE);
	if (new_data == MAP_FAILED)
	{
		perror("mremap");
		return (EXIT_FAILURE);
	}
	elf_handle.data = new_data;
	elf_handle.pht_ph_load_index = num;

	memmove(&((uint8_t *)elf_handle.data)[pht_pos], elf_eh_get_pht(), entsize * num);
	memset(&((uint8_t *)elf_handle.data)[pht_pos + entsize * num], 0, entsize * (n + 1));
	elf_handle.size = pht_pos + pht_new_size;
	elf_eh_set_phoff(pht_pos);
	elf_eh_set_phnum(num + n + 1);

	pht_vaddr = ALIGN_ON(elf_handle.next_available_vaddr + 1, 0x1000UL);
	pht_vaddr += pht_pos % 0x1000;

	printf("%zu\n", elf_eh_get_pht() - elf_handle.data);
	printf("pht pos:   %8zu 0x%05lx\n", pht_pos, pht_pos);
	printf("pht vaddr: %8zu 0x%05lx\n", pht_vaddr, pht_vaddr);
	printf("pht memsz: %8zu 0x%05lx\n", pht_new_size, pht_new_size);

	if (phdr_index < num)
	{
		elf_ph_set_vaddr(phdr_index, pht_vaddr);
		elf_ph_set_paddr(phdr_index, pht_vaddr);
		elf_ph_set_offset(phdr_index, pht_pos);
		elf_ph_set_filesz(phdr_index, pht_new_size);
		elf_ph_set_memsz(phdr_index, pht_new_size);
	}

	elf_ph_set_type(num, PT_LOAD);
	elf_ph_set_flags(num, PF_R);
	elf_ph_set_offset(num, pht_pos);
	elf_ph_set_vaddr(num, pht_vaddr);
	elf_ph_set_paddr(num, pht_vaddr);
	elf_ph_set_filesz(num, pht_new_size);
	elf_ph_set_memsz(num, pht_new_size);
	elf_ph_set_align(num, 0x1000);

	elf_handle.next_available_vaddr = ALIGN_ON(pht_vaddr + pht_new_size, 0x1000);

	return (EXIT_SUCCESS);
}

int		elf_manager_finalize(void)
{
	if (msync(elf_handle.data, elf_handle.size, MS_SYNC))
	{
		perror("msync");
		return (EXIT_FAILURE);
	}
	if (munmap(elf_handle.data, elf_handle.size))
	{
		perror("munmap");
		return (EXIT_FAILURE);
	}
	if (close(elf_handle.fd))
	{
		perror("close");
		return (EXIT_FAILURE);
	}
	return (EXIT_SUCCESS);
}

void		*elf_get_raw_data(void)
{
	return (elf_handle.data);
}

size_t		elf_get_size(void)
{
	return (elf_handle.size);
}

static
int			_get_size(
					int fd,
					size_t *size
					)
{
	off_t	len;

	len = lseek(fd, 0, SEEK_END);
	if (len < 0)
		return (EXIT_FAILURE);
	*size = len;
	len = lseek(fd, 0, SEEK_SET);
	if (len < 0)
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}

static
int			_validate_and_load(void)
{
	const Elf32_Ehdr	*ehdr = elf_handle.data;

	ehdr = elf_handle.data;
	if (elf_handle.size < EI_NIDENT)
		return (EXIT_FAILURE);
	if (memcmp(ehdr->e_ident, ELFMAG, 4))
		return (EXIT_FAILURE);
	switch (ehdr->e_ident[EI_CLASS])
	{
		case 1: int_elf_load_32bit_handlers(); break ;
		case 2: int_elf_load_64bit_handlers(); break ;
		default: return (EXIT_FAILURE);
	}
	switch (ehdr->e_ident[EI_DATA])
	{
		case 1: int_elf_load_le_raw_io(); break ;
		case 2: int_elf_load_be_raw_io(); break ;
		default: return (EXIT_FAILURE);
	}
	elf_handle.next_available_vaddr = _get_next_available_vaddr();
	return (EXIT_SUCCESS);
}

static
size_t		_get_next_available_vaddr(void)
{
	size_t	num;
	size_t	end;
	size_t	last;

	num = elf_eh_get_phnum();
	last = 0;
	while (num--)
	{
		end = elf_ph_get_vaddr(num) + elf_ph_get_memsz(num);
		if (end > last)
			last = end;
	}
	return (last);
}

static
size_t		_get_phdr_index(void)
{
	const size_t	num = elf_eh_get_phnum();;
	size_t			index;

	index = 0;
	while (index < num)
	{
		if (elf_ph_get_type(index) == PT_PHDR)
			return (index);
		++index;
	}
	return (index);
}
