ENTRY(_start)

SECTIONS {
	. = 0x0;
	HIDDEN(stub_begin = .);
	.text : {
		*(.stub.init)
		*(.text)
		*(.rodata*)
		*(.data)
		*(.bss)
		*(.stub.data)
	}
	/DISCARD/ : {
		*(.note*)
		*(.comment)
		*(.eh_frame*)
	}
}
