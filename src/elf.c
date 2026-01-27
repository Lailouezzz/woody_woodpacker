/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   elf.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Antoine Massias <massias.antoine.pro@gm    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/15 14:18:35 by amassias          #+#    #+#             */
/*   Updated: 2025/12/18 13:17:45 by Antoine Mas      ###   ########.fr       */
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
#include <sys/stat.h>

static
int			_get_size(
				int fd,
				size_t *size
				);

static
int			_validate_and_load(
				t_elf_file *s
				);

static
size_t		_get_next_available_vaddr(
				t_elf_file *s
				);

static
size_t		_get_phdr_index(
				t_elf_file *s
				);

int			elf_manager_load(
				t_elf_file *s,
				const char *path
				)
{
	int		fd;
	void	*src;

	fd = open(path, O_RDONLY);
	if (fd < 0)
	{
		return (EXIT_FAILURE);
	}
	if (_get_size(fd, &s->size))
	{
		close(fd);
		return (EXIT_FAILURE);
	}
	src = mmap(NULL,
		s->size,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE,
		fd,
		0
	);
	close(fd);
	if (src == MAP_FAILED)
		return (EXIT_FAILURE);
	s->data = mmap(NULL,
		s->size,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS,
		-1,
		0);
	if (s->data == MAP_FAILED)
		return (EXIT_FAILURE);
	memcpy(s->data, src, s->size);
	if (munmap(src, s->size))
		return (EXIT_FAILURE);
	if (_validate_and_load(s))
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}

int		elf_manager_move_pht_and_emplace_entries(
			t_elf_file *s,
			size_t n
			)
{
	const size_t	num = s->hdl.eh.get.phnum(s);
	const size_t	entsize = s->hdl.eh.get.phentsize(s);
	const size_t	pht_pos = ALIGN_ON(s->size, 8);
	const size_t	pht_new_size = entsize * (num + n + 1);
	const size_t	phdr_index = _get_phdr_index(s);
	size_t			pht_vaddr;
	void			*new_data;

	new_data = mremap(s->data, s->size, pht_pos + pht_new_size, MREMAP_MAYMOVE);
	if (new_data == MAP_FAILED)
		return (EXIT_FAILURE);
	s->data = new_data;
	s->pht_ph_load_index = num;

	memmove(&((uint8_t *)s->data)[pht_pos], s->hdl.eh.get.pht(s), entsize * num);
	memset(&((uint8_t *)s->data)[pht_pos + entsize * num], 0, entsize * (n + 1));
	s->size = pht_pos + pht_new_size;
	s->hdl.eh.set.phoff(s,pht_pos);
	s->hdl.eh.set.phnum(s,num + n + 1);

	pht_vaddr = ALIGN_ON(s->next_available_vaddr + 1, 0x1000UL);
	pht_vaddr += pht_pos % 0x1000;


	if (phdr_index < num)
	{
		s->hdl.ph.set.vaddr(s,phdr_index, pht_vaddr);
		s->hdl.ph.set.paddr(s,phdr_index, pht_vaddr);
		s->hdl.ph.set.offset(s,phdr_index, pht_pos);
		s->hdl.ph.set.filesz(s,phdr_index, pht_new_size);
		s->hdl.ph.set.memsz(s,phdr_index, pht_new_size);
	}

	s->hdl.ph.set.type(s,num, PT_LOAD);
	s->hdl.ph.set.flags(s,num, PF_R);
	s->hdl.ph.set.offset(s,num, pht_pos);
	s->hdl.ph.set.vaddr(s,num, pht_vaddr);
	s->hdl.ph.set.paddr(s,num, pht_vaddr);
	s->hdl.ph.set.filesz(s,num, pht_new_size);
	s->hdl.ph.set.memsz(s,num, pht_new_size);
	s->hdl.ph.set.align(s,num, 0x1000);

	s->next_available_vaddr = ALIGN_ON(pht_vaddr + pht_new_size, 0x1000);

	return (EXIT_SUCCESS);
}

int		elf_append_loadable_data_and_locate(
			t_elf_file *s,
			void *data,
			size_t size,
			size_t align,
			size_t ph_index,
			uint32_t flags
			)
{
	void	*new_data;
	size_t	data_vaddr;

	new_data = mremap(s->data, s->size, s->size + size, MREMAP_MAYMOVE);
	if (new_data == MAP_FAILED)
		return (EXIT_FAILURE);
	s->data = new_data;

	memcpy(&((uint8_t *)s->data)[s->size], data, size);

	data_vaddr = ALIGN_ON(s->next_available_vaddr + 1, align);
	data_vaddr += s->size % align;

	s->hdl.ph.set.type(s,ph_index, PT_LOAD);
	s->hdl.ph.set.flags(s,ph_index, flags);
	s->hdl.ph.set.offset(s,ph_index, s->size);
	s->hdl.ph.set.vaddr(s,ph_index, data_vaddr);
	s->hdl.ph.set.paddr(s,ph_index, data_vaddr);
	s->hdl.ph.set.filesz(s,ph_index, size);
	s->hdl.ph.set.memsz(s,ph_index, size);
	s->hdl.ph.set.align(s,ph_index, align);

	s->next_available_vaddr = data_vaddr;
	s->size += size;
	return (EXIT_SUCCESS);
}

int		elf_manager_finalize(
			t_elf_file *s,
			const char *path
			)
{
	int	r;
	int	fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (fd < 0)
		return (EXIT_FAILURE);
	r = write(fd, s->data, s->size);
	close(fd);
	if (r < 0 || r != (ssize_t)s->size)
		return (EXIT_FAILURE);
	if (munmap(s->data, s->size))
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}

void		*elf_get_raw_data(
				t_elf_file *s
				)
{
	return (s->data);
}

size_t		elf_get_size(
				t_elf_file *s
				)
{
	return (s->size);
}

uint64_t	elf_get_next_vaddr(
				t_elf_file *s
				)
{
	return (s->next_available_vaddr);
}

uint64_t	elf_vaddr_to_offset(
				const t_elf_file *s,
				uint64_t vaddr
				) {
	auto const	phnum = s->hdl.eh.get.phnum(s);

	for (typeof_unqual(phnum) k = phnum; k != 0;) { // Reverse beceause linker is sequential
		--k;
		if (s->hdl.ph.get.type(s, k) == PT_LOAD) {
			auto const	p_vaddr = s->hdl.ph.get.vaddr(s, k);
			auto const	p_filesz = s->hdl.ph.get.memsz(s, k);
			auto const	p_offset = s->hdl.ph.get.offset(s, k);
			if (vaddr >= p_vaddr && vaddr < p_vaddr + p_filesz) {
				return ((vaddr - p_vaddr) + p_offset);
			}
		}
	}
	return (0);
}

int			elf_find_ph_index(
				const t_elf_file *s,
				bool(*cond)(const t_elf_file *s, size_t ph_index)
				) {
	auto const	phnum = s->hdl.eh.get.phnum(s);

	for (typeof_unqual(phnum) k = 0; k < phnum; ++k) {
		if (cond(s, k))
			return (k);
	}
	return (-1);
}

bool		elf_ph_is_dynamic(
				const t_elf_file *s,
				size_t ph_index
				) {
	return (s->hdl.ph.get.type(s, ph_index) == PT_DYNAMIC);
}

static
int			_get_size(
					int fd,
					size_t *size
					)
{
	struct stat	st;

	if (fstat(fd, &st) != 0)
		return (EXIT_FAILURE);
	*size = st.st_size;
	return (EXIT_SUCCESS);
}

static
int			_validate_and_load(
				t_elf_file *s
				)
{
	const Elf32_Ehdr	*ehdr = s->data;

	ehdr = s->data;
	if (s->size < EI_NIDENT)
		return (EXIT_FAILURE);
	if (memcmp(ehdr->e_ident, ELFMAG, 4))
		return (EXIT_FAILURE);
	switch (ehdr->e_ident[EI_CLASS])
	{
		case 1: int_elf_load_32bit_handlers(s); s->is_64 = false; break ;
		case 2: int_elf_load_64bit_handlers(s); s->is_64 = true; break ;
		default: return (EXIT_FAILURE);
	}
	switch (ehdr->e_ident[EI_DATA])
	{
		case 1: int_elf_load_le_raw_io(s); break ;
		case 2: int_elf_load_be_raw_io(s); break ;
		default: return (EXIT_FAILURE);
	}
	s->next_available_vaddr = _get_next_available_vaddr(s);
	return (EXIT_SUCCESS);
}

static
size_t		_get_next_available_vaddr(
				t_elf_file *s
				)
{
	size_t	num;
	size_t	end;
	size_t	last;

	num = s->hdl.eh.get.phnum(s);
	last = 0;
	while (num--)
	{
		end = s->hdl.ph.get.vaddr(s, num) + s->hdl.ph.get.memsz(s, num);
		if (end > last)
			last = end;
	}
	return (last);
}

static
size_t		_get_phdr_index(
				t_elf_file *s
				)
{
	const size_t	num = s->hdl.eh.get.phnum(s);
	size_t			index;

	index = 0;
	while (index < num)
	{
		if (s->hdl.ph.get.type(s, index) == PT_PHDR)
			return (index);
		++index;
	}
	return (index);
}
