#ifndef  STUB_64_STUB_H
# define STUB_64_STUB_H

// ---
// Includes
// ---

# include <stdint.h>
# include "stub_def.h"

// ---
// Defines
// ---

// ---
// Typedefs
// ---

// ---
// Global variables
// ---

__attribute__((section(".stub.data")))
extern t_stub_64_data	g_stub_data;

// ---
// Function declartions
// ---

const char	*get_self_path();

int	fgetchar(int fd);

uint64_t	fgethex(int fd);

size_t	read_maps(char **buf);

void	decrypt(const t_range *protected_ranges, uint64_t ranges_len);

void	ft_putstr(const char *s);

void	ft_puthex(uint64_t nb);

void	ft_putnbr(uint64_t nb);

#endif
