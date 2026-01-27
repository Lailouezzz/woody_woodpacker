// ---
// Includes
// ---

#define _GNU_SOURCE
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

// ---
// Defines
// ---

#define ishex(c) ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))

// ---
// Static function declarations
// ---



// ---
// Extern function definitions
// ---

const char	*get_self_path() {
	static char	buf[0x1000] = {0};
	return readlink("/proc/self/exe", buf, sizeof(buf)) > 0 ? buf : "";
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
			buf[i--] = nb % 16 + 'A' - 10;
		}
		nb /= 16;
	}
	write(STDOUT_FILENO, &buf[i], sizeof(buf)-i);
	write(STDOUT_FILENO, "\n", 1);
}

void	skip_spaces(char **s) {
	while (**s == ' ' || **s == '\t')
		++(*s);
}

void	skip_to_nl(char **s) {
	while (**s != '\n' && **s)
		++(*s);
}

void	decrypt() {
	char	*maps;
	size_t	maps_size = read_maps(&maps);
	uintptr_t	start_vaddr;
	uintptr_t	end_vaddr;
	uint64_t	off;
	int	prev_perm = 0;

	ft_putstr("PARSING MAPPINGS\n");
	ft_putstr(maps);
	while (*maps) {
		start_vaddr = parse_hex(&maps);
		++maps; // -
		end_vaddr = parse_hex(&maps);
		skip_spaces(&maps);
		if (*maps != '-')
			prev_perm |= PROT_READ;
		if (*(++maps) != '-')
			prev_perm |= PROT_WRITE;
		maps += 3;
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
		skip_to_nl(&maps);
		++maps;
		ft_putstr("START VADDR: ");
		ft_puthex(start_vaddr);
		ft_putstr("END VADDR: ");
		ft_puthex(end_vaddr);
		ft_putstr("OFF: ");
		ft_puthex(off);
	}

	munmap(maps, maps_size);
}


// ---
// Static function definitions
// ---
