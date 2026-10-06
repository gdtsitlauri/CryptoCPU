# Signed overflow traps precisely: the store before it retires, the one after does not.
# EXPECT status trap-overflow
# EXPECT mem before 1
# EXPECT mem after 0
        .data
before: .word 0
after:  .word 0
        .text
main:   la    $s0, before
        la    $s1, after
        li    $t0, 1
        sw    $t0, 0($s0)
        li    $t1, 0x7fffffff
        addi  $t2, $t1, 1
        sw    $t0, 0($s1)
        li    $v0, 10
        syscall
