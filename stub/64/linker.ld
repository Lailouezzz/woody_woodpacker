ENTRY(_start)

SECTIONS {
	. = 0x0;
	stub_begin = .;
	.text : {
		*(.stub_init)
		*(.text)
		*(.rodata*)
		*(.data)
	}
	/DISCARD/ : {
		*(.note*)
		*(.comment)
		*(.eh_frame*)
	}
}
