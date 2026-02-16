#ifndef  STUB_64_STUB_DEF_H
# define STUB_64_STUB_DEF_H

// ---
// Includes
// ---

# include <stdint.h>
# include "protect_range.h"

// ---
// Defines
// ---



// ---
// Typedefs
// ---

typedef struct {
	uint64_t	stub_virt_off;
	uint64_t	entry_point;
	uint64_t	ranges_ptr;
	uint64_t	ranges_len;
	uint64_t	bss_ranges_ptr;
	uint64_t	bss_ranges_len;
}	t_stub_64_data;

// ---
// Function declartions
// ---



#endif
