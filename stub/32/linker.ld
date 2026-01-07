ENTRY(_start)

SECTIONS {
	. = 0x0;
	HIDDEN(stub_begin = .);
	.text : {
		*(.stub.init)
		*(.text)
		*(.text.*)
		*(.rodata*)
		*(.data)
		*(.data.rel*)
		. = ALIGN(4);
		*(.got.plt)
		*(.got)
		*(.bss)
		. = ALIGN(8);
		*(.stub.data)
		HIDDEN(stub_data_end = .);
	}
	ASSERT(stub_data_end == ., "Padding after stub data")
	/DISCARD/ : {
		*(*)
		*(.note*)
		*(.comment)
		*(.eh_frame*)
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
