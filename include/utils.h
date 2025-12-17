/**
 * @file utils.h
 * @brief Utility macros and helper functions.
 */

#ifndef  UTILS_H
# define UTILS_H

// ---
// Includes
// ---

# include <stdlib.h>
# include <stdio.h>
# include <stddef.h>
# include <stdint.h>
# include <string.h>
# include <stdbool.h>

// ---
// Defines
// ---

/**
 * @brief Generic dynamic list structure.
 * @param T Element type.
 */
# define list(T) struct { T *data; size_t cap; size_t len; }

/**
 * @brief Typedef helper for list types.
 * @param T Element type.
 * @param name Type name prefix (creates name_t).
 */
# define TYPEDEF_LIST(T, name) typedef list(T) name##_t

/**
 * @brief Initialize an empty list.
 */
# define list_new() { .data = NULL, .cap = 0, .len = 0 }

/**
 * @brief Free a list and reset its state.
 * @param l Pointer to the list.
 */
# define list_free(l) do { \
	if ((l)->data != NULL) free((l)->data); \
	(l)->data = NULL; \
	(l)->cap = 0; \
	(l)->len = 0; \
} while (0)

/**
 * @brief Reserve capacity for list elements.
 * @param l Pointer to the list.
 * @param capacity New capacity.
 * @return true on success, false on allocation failure.
 */
# define list_reserve(l, capacity) ({ \
	void *__tmp = realloc((l)->data, (capacity) * sizeof(*(l)->data)); \
	if (__tmp != NULL) { \
		(l)->data = __tmp; \
		(l)->cap = (capacity); \
	} \
	(__tmp != NULL); \
	})

/**
 * @brief Push an element to the list.
 * @param l Pointer to the list.
 * @param v Value to push.
 * @return true on success, false on allocation failure.
 */
# define list_push(l, v) ({ \
	bool _success = true; \
	if ((l)->len >= (l)->cap) { \
		_success = list_reserve(l, (l)->cap != 0 ? (l)->cap << 1 : 8); \
	} \
	if (_success) { \
		(l)->data[(l)->len++] = (v); \
	} \
	_success; \
	})

/**
 * @brief Push a list to the list.
 * @param l Pointer to the list.
 * @param p Pointer to push elements.
 * @param n Elem count.
 * @return true on success, false on allocation failure.
 */
# define list_push_range(l, p, n) ({ \
	(void)sizeof(*(l)->data = *(p)); \
	bool _success = true; \
	if ((l)->len + (n) > (l)->cap) { \
		_success = list_reserve(l, stdc_bit_ceil((l)->len + (n))); \
	} \
	if (_success) { \
		memcpy((l)->data + (l)->len, p, (size_t)(n) * sizeof(*(l)->data)); \
		(l)->len += (n); \
	} \
	_success; \
	})

/**
 * @brief Iterate over list elements.
 * @param l Pointer to the list.
 * @param it Iterator variable (pointer to element).
 */
# define list_foreach(l, it) \
	for (size_t _i = 0; _i < (l)->len && ((it) = &(l)->data[_i], 1); _i++)

/**
 * @brief Iterate over array elements.
 * @param array Static array.
 * @param it Iterator variable (pointer to element).
 */
# define array_foreach(array, it) \
	for (size_t _i = 0; _i < ELEM_COUNT(array) && ((it) = &(array)[_i], 1); _i++)

/**
 * @brief Return the maximum of two values.
 */
# define MAX(a, b) ((a) > (b) ? (a) : (b))

/**
 * @brief Return the minimum of two values.
 */
# define MIN(a, b) ((a) < (b) ? (a) : (b))

/**
 * @brief Return the absolute value.
 */
# define ABS(a) (((a) < 0) ? (-(a)) : (a))

/**
 * @brief Get element count of a static array.
 */
# define ELEM_COUNT(container) (sizeof(container) / sizeof(*container))

/**
 * @brief Mark a variable as unused.
 */
# define UNUSED(var) ((void)var);

// ---
// Typedefs
// ---

TYPEDEF_LIST(char, bytes);

// ---
// Function declarations
// ---

/**
 * @brief Print error message with program name.
 * @param fmt printf-style format string.
 * @param ... Format arguments.
 */
void	error_msg(const char *fmt, ...);

/**
 * @brief Print error message with program name and errno.
 * @param fmt printf-style format string.
 * @param ... Format arguments.
 */
void	perror_msg(const char *fmt, ...);

/**
 * @brief Print verbose message if verbose mode is enabled.
 * @param fmt printf-style format string.
 * @param ... Format arguments.
 */
void	verbose(const char *fmt, ...);

/**
 * @brief Enable verbose
 * @param verbose
 */
void	set_verbose(bool verbose);

/**
 * @brief Set the global program name
 *
 * @param pn
 */
void	set_pn(const char *pn);

// ---
// Static inline function
// ---

static inline size_t stdc_bit_ceil(size_t n) {
	if (n <= 1) return 1;
	return 1UL << (64 - __builtin_clzl(n - 1));
}

#endif
