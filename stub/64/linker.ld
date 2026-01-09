ENTRY(_start)

SECTIONS {
	. = 0x0;
	HIDDEN(stub_begin = .);
	.text : {
		*(.stub.init)
		*(.text)
		*(.rodata*)
		*(.data)
		*(.data.rel*)
		*(.bss)
		. = ALIGN(8);
		*(.stub.data)
		HIDDEN(stub_end = .);
	}
	ASSERT(stub_end == ., "Padding after stub data")
	/DISCARD/ : {
		*(*)
		*(.note*)
		*(.comment)
		*(.eh_frame*)
		*(.got*)
		*(.plt*)
		*(.rela*)
		*(.dynsym)
		*(.dynstr)
		*(.hash)
		*(.gnu.hash)
		*(.shstrtab)
		*(.symtab)
		*(.strtab)
	}
}
