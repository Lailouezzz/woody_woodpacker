/**
 * @file stub.h
 * @brief 32-bit stub declarations.
 */

#ifndef STUB_32_STUB_H
#define STUB_32_STUB_H

// ---
// Includes
// ---

#include <stddef.h>
#include <stdint.h>
#include "stub_def.h"
#include "protect_range.h"

// ---
// Global variables
// ---

/** @brief Stub data populated by the packer. */
__attribute__((section(".stub.data")))
extern t_stub_32_data	g_stub_data;

// ---
// Function declarations
// ---

/**
 * @brief Decrypt all self-mappings using protected ranges.
 * @param base Base address of the loaded binary.
 * @param protected_ranges Array of ranges to skip during decryption.
 * @param ranges_len Number of protected ranges.
 * @param bss_ranges_ptr Array of BSS ranges (unmapped memory).
 * @param bss_ranges_len Number of BSS ranges.
 */
void	decrypt(
			uintptr_t base,
			t_range *protected_ranges,
			uint64_t ranges_len,
			t_range *bss_ranges_ptr,
			uint64_t bss_ranges_len);

bool	elf_load(
			const char *path,
			void **base,
			void **entry);

#endif
