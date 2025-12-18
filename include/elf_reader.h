/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   elf_reader.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Antoine Massias <massias.antoine.pro@gm    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/15 14:05:14 by amassias          #+#    #+#             */
/*   Updated: 2025/12/18 11:10:01 by Antoine Mas      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef ELF_READER_H
# define ELF_READER_H

# include <elf.h>
# include <stdlib.h>
# include <stdint.h>

extern uint64_t	(*elf_eh_get_entry)(void);

extern uint64_t	(*elf_eh_get_phoff)(void);
extern uint16_t	(*elf_eh_get_phentsize)(void);
extern uint16_t	(*elf_eh_get_phnum)(void);
extern void		*(*elf_eh_get_pht)();
extern void		*(*elf_eh_get_ph)(size_t);

extern void		(*elf_eh_set_entry)(uint64_t);
extern void		(*elf_eh_set_phoff)(uint64_t);
extern void		(*elf_eh_set_phentsize)(uint16_t);
extern void		(*elf_eh_set_phnum)(uint16_t);

extern uint64_t	(*elf_eh_get_shoff)(void);
extern uint16_t	(*elf_eh_get_shentsize)(void);
extern uint16_t	(*elf_eh_get_shnum)(void);
extern void		*(*elf_eh_get_sht)();
extern void		*(*elf_eh_get_sh)(size_t);

extern void		(*elf_eh_set_shoff)(uint64_t);
extern void		(*elf_eh_set_shentsize)(uint16_t);
extern void		(*elf_eh_set_shnum)(uint16_t);

extern uint32_t	(*elf_ph_get_type)(size_t);
extern uint32_t	(*elf_ph_get_flags)(size_t);
extern uint64_t	(*elf_ph_get_offset)(size_t);
extern uint64_t	(*elf_ph_get_vaddr)(size_t);
extern uint64_t	(*elf_ph_get_paddr)(size_t);
extern uint64_t	(*elf_ph_get_filesz)(size_t);
extern uint64_t	(*elf_ph_get_memsz)(size_t);
extern uint64_t	(*elf_ph_get_align)(size_t);

extern void		(*elf_ph_set_type)(size_t, uint32_t);
extern void		(*elf_ph_set_flags)(size_t, uint32_t);
extern void		(*elf_ph_set_offset)(size_t, uint64_t);
extern void		(*elf_ph_set_vaddr)(size_t, uint64_t);
extern void		(*elf_ph_set_paddr)(size_t, uint64_t);
extern void		(*elf_ph_set_filesz)(size_t, uint64_t);
extern void		(*elf_ph_set_memsz)(size_t, uint64_t);
extern void		(*elf_ph_set_align)(size_t, uint64_t);

extern uint32_t	(*elf_sh_get_name)(size_t);
extern uint32_t	(*elf_sh_get_type)(size_t);
extern uint64_t	(*elf_sh_get_flags)(size_t);
extern uint64_t	(*elf_sh_get_addr)(size_t);
extern uint64_t	(*elf_sh_get_offset)(size_t);
extern uint64_t	(*elf_sh_get_size)(size_t);
extern uint32_t	(*elf_sh_get_link)(size_t);
extern uint32_t	(*elf_sh_get_info)(size_t);
extern uint64_t	(*elf_sh_get_addralign)(size_t);
extern uint64_t	(*elf_sh_get_entsize)(size_t);

extern void		(*elf_sh_set_name)(size_t, uint32_t);
extern void		(*elf_sh_set_type)(size_t, uint32_t);
extern void		(*elf_sh_set_flags)(size_t, uint64_t);
extern void		(*elf_sh_set_addr)(size_t, uint64_t);
extern void		(*elf_sh_set_offset)(size_t, uint64_t);
extern void		(*elf_sh_set_size)(size_t, uint64_t);
extern void		(*elf_sh_set_link)(size_t, uint32_t);
extern void		(*elf_sh_set_info)(size_t, uint32_t);
extern void		(*elf_sh_set_addralign)(size_t, uint64_t);
extern void		(*elf_sh_set_entsize)(size_t, uint64_t);

int			elf_manager_load(
				const char *path
				);

void		*elf_get_raw_data(void);

size_t		elf_get_size(void);

uint64_t	elf_get_next_vaddr(void);

int			elf_manager_move_pht_and_emplace_entries(
				size_t n
				);

int			elf_append_loadable_data_and_locate(
				void *data,
				size_t size,
				size_t align,
				size_t ph_index,
				uint32_t flags
				);

int			elf_manager_finalize(void);

#endif
