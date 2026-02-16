// ---
// Includes
// ---

#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "protect_range.h"
#include "utils.h"
#include "encrypt.h"

// ---
// Defines
// ---

#define ishex(c) ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))

// ---
// Static function declarations
// ---

static void	_decrypt_mapping(const t_ranges *ranges, uintptr_t start_vaddr, uintptr_t end_vaddr, off_t off);

static uint64_t	_get_next_bss_off(const t_ranges *bss_ranges, uint64_t start_vaddr, uint64_t base);

// ---
// Extern function definitions
// ---

const char	*get_self_path() {
	static char	buf[0x1000] = {0};
	return readlink("/proc/self/exe", buf, sizeof(buf)) > 0 ? buf : "UNK";
}

int	fgetchar(int fd) {
	char	c;
	auto ret = read(fd, &c, 1);
	if (ret <= 0) {
		return -1;
	}
	return c;
}

uint64_t	fgethex(int fd) {
	int hex;
	uint64_t nb = 0;
	hex = fgetchar(fd);
	while (ishex(hex)) {
		nb <<= 4;
		if (hex >= '0' && hex <= '9') {
			nb += hex - '0';
		} else {
			nb += hex - 'a' + 10;
		}
		hex = fgetchar(fd);
	}
	return nb;
}

size_t	read_maps(char **buf) {
	int	fd = open("/proc/self/maps", O_RDONLY);
	size_t	size = 0x1000;
	*buf = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	size_t	off = 0;
	ssize_t	ret;
	while ((ret = read(fd, (char *)*buf+off, 0x1000)) == 0x1000) {
		*buf = mremap(*buf, size, size + 0x1000, MREMAP_MAYMOVE);
		size += 0x1000;
		off += 0x1000;
	}
	close(fd);
	if (ret < 0)
		return 0;
	((char *)*buf)[off+ret] = '\0';
	return size;
}

uint64_t	parse_hex(char **s) {
	uint64_t nb = 0;
	while (ishex(**s)) {
		nb <<= 4;
		if (**s >= '0' && **s <= '9') {
			nb += **s - '0';
		} else {
			nb += **s - 'a' + 10;
		}
		++(*s);
	}
	return nb;
}

void	ft_putstr(const char *s) {
	while (*s) {
		write(STDOUT_FILENO, s++, 1);
	}
}

void	ft_puthex(uint64_t nb) {
	char	buf[2 * sizeof(nb)] = {0};
	int i = sizeof(buf) - 1;
	buf[i] = '0';
	while (nb != 0) {
		if (nb % 16 < 10) {
			buf[i--] = nb % 16 + '0';
		} else {
			buf[i--] = nb % 16 + 'a' - 10;
		}
		nb /= 16;
	}
	write(STDOUT_FILENO, &buf[i], sizeof(buf)-i);
}

void	skip_spaces(char **s) {
	while (**s == ' ' || **s == '\t')
		++(*s);
}

void	skip_to_nl(char **s) {
	while (**s != '\n' && **s)
		++(*s);
}

void	decrypt(uintptr_t base, t_range *protected_ranges, uint64_t ranges_len, t_range *bss_ranges_ptr, uint64_t bss_ranges_len) {
	char	*maps;
	size_t	maps_size = read_maps(&maps);
	uintptr_t	start_vaddr;
	uintptr_t	end_vaddr;
	uint64_t	off;
	const char	*self_path = get_self_path();
	bool		is_self;
	const t_ranges	ranges = {.data = protected_ranges, .len = ranges_len};
	const t_ranges	bss_ranges = {.data = bss_ranges_ptr, .len = bss_ranges_len};
	int	prev_perm = 0;

	while (*maps) {
		prev_perm = 0;
		start_vaddr = parse_hex(&maps);
		++maps; // -
		end_vaddr = parse_hex(&maps);
		skip_spaces(&maps);
		if (*maps != '-')
			prev_perm |= PROT_READ;
		if (*(++maps) != '-')
			prev_perm |= PROT_WRITE;
		if (*(++maps) != '-')
			prev_perm |= PROT_EXEC;
		maps += 2;
		skip_spaces(&maps);
		off = parse_hex(&maps);
		skip_spaces(&maps);
		parse_hex(&maps);
		++maps;
		parse_hex(&maps);
		skip_spaces(&maps);
		parse_hex(&maps);
		skip_spaces(&maps);
		// HERE IS THE PATH
		is_self = memcmp(maps, self_path, strlen(self_path)) == 0 && maps[strlen(self_path)] == '\n';
		skip_to_nl(&maps);
		++maps;
		if (!is_self)
			continue ;
		const uint64_t next_bss_off = _get_next_bss_off(&bss_ranges, start_vaddr, base);
		if (next_bss_off != 0)
			end_vaddr = MIN(next_bss_off, end_vaddr);
		mprotect((void*)start_vaddr, end_vaddr - start_vaddr, PROT_EXEC | PROT_WRITE | PROT_READ);
		_decrypt_mapping(&ranges, start_vaddr, end_vaddr-1, off);
		mprotect((void*)start_vaddr, end_vaddr - start_vaddr, prev_perm);
	}

	// ft_putstr(self_path);

	munmap(maps, maps_size);
}


// ---
// Static function definitions
// ---
 
static uint64_t	_get_next_bss_off(const t_ranges *bss_ranges, uint64_t start_vaddr, uint64_t base) {
	size_t vaddr = 0;
	size_t k = 0;
	while (k < bss_ranges->len && vaddr < start_vaddr) {
		vaddr = bss_ranges->data[k].off + base;
		++k;
	}
	return (vaddr);
} 

static void	_decrypt_mapping(const t_ranges *ranges, uintptr_t start_vaddr, uintptr_t end_vaddr, off_t off) {
	size_t	range_idx = 0;

	while (range_idx < ranges->len && ranges->data[range_idx].off < off) {
		++range_idx;
	}
	for (size_t k = MAX(1, range_idx); k < ranges->len; ++k) {
		auto const	begin_vaddr = MAX(start_vaddr, ALIGN_UP(ranges->data[k - 1].off + ranges->data[k - 1].len - 1, 8) + start_vaddr - off);
		if (begin_vaddr > end_vaddr)
			return ;
		auto const	size = MIN(((off_t)ALIGN_DOWN(ranges->data[k].off, 8)) - (begin_vaddr - start_vaddr) - off, end_vaddr - begin_vaddr + 1);
		if (size == 0 || ALIGN_UP(ranges->data[k - 1].off + ranges->data[k - 1].len - 1, 8) >= ALIGN_DOWN(ranges->data[k].off, 8))
			continue ;
		ft_putstr("0x");
		ft_puthex(begin_vaddr - start_vaddr + off);
		ft_putstr(" => 0x");
		ft_puthex(begin_vaddr - start_vaddr + off + size - 1);
		ft_putstr("\n");
		xtea_decrypt((void*)(uintptr_t)begin_vaddr, size, (const uint32_t *)"1234567812345678");
	}
}
