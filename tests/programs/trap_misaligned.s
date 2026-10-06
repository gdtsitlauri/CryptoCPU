# A misaligned load traps in MEM; younger instructions do not retire.
# EXPECT status trap-mem
# EXPECT mem flag 0
        .data
x:      .word 0x11223344
flag:   .word 0
        .text
main:   la    $t0, x
        lw    $t1, 2($t0)
        li    $t2, 1
        la    $t3, flag
        sw    $t2, 0($t3)
        li    $v0, 10
        syscall
