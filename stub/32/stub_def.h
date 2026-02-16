#ifndef  STUB_32_STUB_DEF_H
# define STUB_32_STUB_DEF_H

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
	uint32_t	stub_virt_off;
	uint32_t	entry_point;
	uint32_t	ranges_ptr;
	uint32_t	ranges_len;
	uint32_t	bss_ranges_ptr;
	uint32_t	bss_ranges_len;
}	t_stub_32_data;

// ---
// Function declartions
// ---



#endif
