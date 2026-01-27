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
	t_ranges	ranges;
}	t_stub_64_data;

// ---
// Function declartions
// ---



#endif
