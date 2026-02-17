/**
 * @file stub_def.h
 * @brief 32-bit stub data structure definition.
 */

#ifndef STUB_32_STUB_DEF_H
#define STUB_32_STUB_DEF_H

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
	uint32_t	stub_virt_off;   /**< Stub's virtual address offset. */
	uint32_t	entry_point;     /**< Original program entry point. */
	uint32_t	ranges_ptr;      /**< Protected ranges array vaddr. */
	uint32_t	ranges_len;      /**< Number of protected ranges. */
	uint32_t	bss_ranges_ptr;  /**< BSS ranges array vaddr. */
	uint32_t	bss_ranges_len;  /**< Number of BSS ranges. */
}	t_stub_32_data;

#endif
