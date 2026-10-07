# Labels must follow automatic/explicit data padding before loads execute.
# EXPECT status halt
# EXPECT reg $t1 0x1234
# EXPECT reg $t3 0x12345678
# EXPECT reg $t5 7
# EXPECT reg $t7 9
# EXPECT reg $t0 0x10010002
# EXPECT reg $t2 0x10010008
# EXPECT reg $t4 0x10010010
# EXPECT reg $t6 0x10010020

        .data
        .byte 0xaa
half:   .half 0x1234
        .byte 0xbb
word:   .word 0x12345678
        .asciiz "x"
alias:
standalone:
        .word 7
        .byte 0xcc
aligned: .align 4
        .word 9

        .text
        la $t0, half
        lhu $t1, 0($t0)
        la $t2, word
        lw $t3, 0($t2)
        la $t4, standalone
        lw $t5, 0($t4)
        la $t6, aligned
        lw $t7, 0($t6)
        li $v0, 10
        syscall
