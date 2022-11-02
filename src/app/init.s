.globl INIT
INIT:
	la	a0, bss_start
	la	a1, bss_end
	bgeu	a0, a1, 2f
1:
	sw	zero, (a0)
	addi	a0, a0, 4
	bltu	a0, a1, 1b
2: