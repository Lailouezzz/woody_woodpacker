#ifndef  PROTECT_RANGE_H
# define PROTECT_RANGE_H

// ---
// Includes
// ---

# include <sys/types.h>
# include "elf_reader.h"
# include "utils.h"

// ---
// Defines
// ---

# define MAKE_RANGE(_off, _len) (t_range){ .off = (_off), .len = (_len) }

// ---
// Typedefs
// ---

typedef struct s_range {
	off_t	off;
	size_t	len;
}	t_range;

TYPEDEF_LIST(t_range, ranges);

// ---
// Function declartions
// ---

/**
 * @brief 
 *
 * @param elf 
 * @param ranges 
 * @return true success; false error
 */
bool	elf_get_protected_ranges(
			const t_elf_file *elf,
			t_ranges *ranges
			);

#endif
