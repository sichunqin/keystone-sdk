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
    PROVIDE(protocol_version = .);
    . += 0x1;

    PROVIDE(public_key = .);
    . += 0x20;

    PROVIDE(public_key_signature = .);
    . += 0x40;

    PROVIDE(image_signature = .);
    . += 0x40;

    PROVIDE(encrypted_enc_key = .);
    . += 0x10;
  }
  .bss : { *(.bss) }

  . = ALIGN(0x1000);

  _end = .;
}
