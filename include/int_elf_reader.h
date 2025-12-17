/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   int_elf_reader.h                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: Antoine Massias <massias.antoine.pro@gm    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/12/16 09:03:30 by amassias          #+#    #+#             */
/*   Updated: 2025/12/17 17:24:57 by Antoine Mas      ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef INT_ELF_READER_H
# define INT_ELF_READER_H

# include "elf_reader.h"

typedef struct s_elf_file
{
	int				fd;
	size_t			size;
	void			*data;
	size_t			next_available_vaddr;
	size_t			pht_ph_load_index;
}	t_elf_file;

extern uint8_t		(*read8)(const void *, size_t);
extern uint16_t		(*read16)(const void *, size_t);
extern uint32_t		(*read32)(const void *, size_t);
extern uint64_t		(*read64)(const void *, size_t);
extern void			(*write8)(void *, size_t, uint8_t);
extern void			(*write16)(void *, size_t, uint16_t);
extern void			(*write32)(void *, size_t, uint32_t);
extern void			(*write64)(void *, size_t, uint64_t);

extern t_elf_file	elf_handle;

void	int_elf_load_32bit_handlers(void);
void	int_elf_load_64bit_handlers(void);

void	int_elf_load_le_raw_io(void);
void	int_elf_load_be_raw_io(void);

#endif
