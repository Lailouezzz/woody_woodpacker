/**
 * @file stub_def.h
 * @brief 64-bit stub data structure definition.
 */

#ifndef STUB_64_STUB_DEF_H
#define STUB_64_STUB_DEF_H

// ---
// Includes
// ---

#include <stdint.h>
#include "protect_range.h"

// ---
// Typedefs
// ---

/**
 * @brief Stub metadata populated by the packer.
 *
 * This structure is embedded in the stub's .stub.data section and filled
 * at pack time with runtime decryption parameters.
 */
typedef struct {
	uint64_t	stub_virt_off;   /**< Stub's virtual address offset. */
	uint64_t	entry_point;     /**< Original program entry point. */
	uint64_t	ranges_ptr;      /**< Protected ranges array vaddr. */
	uint64_t	ranges_len;      /**< Number of protected ranges. */
	uint64_t	bss_ranges_ptr;  /**< BSS ranges array vaddr. */
	uint64_t	bss_ranges_len;  /**< Number of BSS ranges. */
}	t_stub_64_data;

#endif
