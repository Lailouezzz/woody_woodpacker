#include <elf.h>
#include <unistd.h>
#include "stub.h"
#include "elf_reader.h"

__attribute__((section(".stub.data")))
stub_64_data_t	g_stub_data = {.entry_point = 0x4242, .stub_virt_off = 0x4242};
extern char	stub_begin[];
static char	*_base;

static void _inject_other() {
	t_elf_file	elf;
	write(STDOUT_FILENO, "LOADING\n", 8);
	if (elf_manager_load(&elf, "test"))
		return ;
	write(STDOUT_FILENO, "EDITING\n", 8);
	if (elf_manager_move_pht_and_emplace_entries(&elf, 0))
		return ;
	write(STDOUT_FILENO, "FINALIZING\n", 11);
	if (elf_manager_finalize(&elf))
		return ;
}

void (*get_truc())() {
	return _inject_other;
}

void *stub_main(void) {
	_base = (char*)stub_begin - g_stub_data.stub_virt_off;
	_inject_other();
	return (g_stub_data.entry_point + _base);
}
