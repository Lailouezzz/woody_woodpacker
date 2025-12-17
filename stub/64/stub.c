#include <elf.h>
#include "stub.h"

__attribute__((section(".stub.data")))
stub_64_data_t	g_stub_data;
__attribute__((visibility("hidden"))) // RIP RELATIVE
extern char	stub_begin[];
static char	*_base;

void *stub_main(void) {
	_base = (char*)stub_begin - g_stub_data.stub_virt_off;
	return (g_stub_data.entry_point + _base);
}
