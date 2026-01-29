#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include "stub.h"
#include "elf_reader.h"

__attribute__((section(".stub.data")))
t_stub_64_data	g_stub_data = {.entry_point = 0x4242, .stub_virt_off = 0x4242};
extern char	stub_begin[];
extern char	stub_end[];
static char	*_base;

void *stub_main(void) {
	_base = (char*)stub_begin - g_stub_data.stub_virt_off;
	g_stub_data.ranges_ptr = (uintptr_t)(g_stub_data.ranges_ptr + _base);
	decrypt((const t_range *)g_stub_data.ranges_ptr, g_stub_data.ranges_len);
	return (g_stub_data.entry_point + _base);
}
