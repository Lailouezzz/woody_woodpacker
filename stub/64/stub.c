#include <elf.h>
#include <unistd.h>
#include "stub.h"
#include "elf_reader.h"

__attribute__((section(".stub.data")))
t_stub_64_data	g_stub_data = {.entry_point = 0x4242, .stub_virt_off = 0x4242};
extern char	stub_begin[];
extern char	stub_end[];
static char	*_base;

static void _inject_other() {
	t_elf_file	elf;
	write(STDOUT_FILENO, "LOADING\n", 8);
	if (elf_manager_load(&elf, "test"))
		return ;
	write(STDOUT_FILENO, "EDITING\n", 8);
	if (elf_manager_move_pht_and_emplace_entries(&elf, 1))
		return ;
	write(STDOUT_FILENO, "FINALIZING\n", 11);
	if (elf_manager_finalize(&elf, "woody"))
		return ;
}

void	ft_puthex(uint64_t nb) {
	char	buf[2 * sizeof(nb)] = {0};
	const char *a = "0123456789ABCDEF";
	int i = sizeof(buf) - 1;
	buf[i] = '0';
	while (nb != 0) {
		buf[i--] = a[nb % 16];
		nb /= 16;
	}
	write(STDOUT_FILENO, &buf[i], sizeof(buf)-i);
	write(STDOUT_FILENO, "\n", 1);
}

void	ft_putnbr(uint64_t nb) {
	char	buf[32] = {0};
	int i = 31;
	buf[i] = '0';
	while (nb != 0) {
		buf[i--] = '0' + nb % 10;
		nb /= 10;
	}
	write(STDOUT_FILENO, &buf[i], sizeof(buf)-i);
	write(STDOUT_FILENO, "\n", 1);
}

void *stub_main(void) {
	_base = (char*)stub_begin - g_stub_data.stub_virt_off;
	g_stub_data.ranges.data = (t_range *)((uintptr_t)g_stub_data.ranges.data + _base);
	ft_putnbr(g_stub_data.ranges.len);
	ft_puthex((uintptr_t)g_stub_data.ranges.data);
	list_foreach(&g_stub_data.ranges, it) {
		ft_puthex(it->off);
		ft_puthex(it->len);
	}
	_inject_other();
	return (g_stub_data.entry_point + _base);
}
