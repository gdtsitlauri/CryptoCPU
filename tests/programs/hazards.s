# Forwarding, load-use stalls, store after load, branch on a loaded value,
# a squashed wrong-path instruction, and call/return dependencies.
# EXPECT status halt
# EXPECT mem out+0 45
# EXPECT mem out+4 45
# EXPECT mem out+12 6
# EXPECT mem out+16 45
# EXPECT reg $t1 10
# EXPECT reg $t4 21
# EXPECT reg $t5 11
        .data
vals:   .word 5, 9, 12, 0
out:    .space 32
        .text
main:   la    $s0, vals
        la    $s1, out
        lw    $t0, 0($s0)
        addu  $t1, $t0, $t0
        lw    $t2, 4($s0)
        lw    $t3, 8($s0)
        addu  $t4, $t2, $t3
        sub   $t5, $t4, $t1
        sll   $t6, $t5, 2
        or    $t7, $t6, $t0
        sw    $t7, 0($s1)
        lw    $t8, 0($s1)
        sw    $t8, 4($s1)
        lw    $t9, 12($s0)
        beqz  $t9, skip
        li    $t7, 999
skip:   jal   leaf
        addu  $s2, $v0, $ra
        sw    $s2, 8($s1)
        li    $a0, 3
        li    $s3, 0
again:  addu  $s3, $s3, $a0
        addiu $a0, $a0, -1
        bnez  $a0, again
        sw    $s3, 12($s1)
        sw    $t7, 16($s1)
        li    $v0, 10
        syscall
leaf:   addiu $v0, $zero, 7
        jr    $ra
