OUTPUT_ARCH( "riscv" )

SECTIONS
{
  . = 0x00001000;
  .text : {
    *(.text._start)
    *(.text)
  }
  . = ALIGN(0x1000);
  .rodata :
  {
    *(.rdata)
    *(.rodata)
  }
  .data : { *(.data) }
  . = ALIGN(0x1000);
  .embed : {
    /* 4 bytes magic number !emb */
    BYTE(33)
    BYTE(101)
    BYTE(109)
    BYTE(98)
    PROVIDE(embed_data = .);
    . += 300;
  }
  .bss :
  {
    PROVIDE(bss_start = .);
    *(.bss)
    PROVIDE(bss_end = .);
  }
  _end = .;
}
