#include <elf.h>
#include <unistd.h>
#include "stub.h"
#include "elf_reader.h"

__attribute__((section(".stub.data")))
t_stub_32_data	g_stub_data = {.entry_point = 0x4242, .stub_virt_off = 0x4242};
extern char	stub_begin[];
static char	*_base;

void *stub_main(void) {
	_base = (char*)stub_begin - g_stub_data.stub_virt_off;
	decrypt();
	return (g_stub_data.entry_point + _base);
}
