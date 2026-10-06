# Multiply and divide, signed and unsigned, through HI/LO and mul.
# EXPECT status halt
# EXPECT mem res+0 -21
# EXPECT mem res+4 -1
# EXPECT mem res+8 -2
# EXPECT mem res+12 -1
# EXPECT mem res+16 1
# EXPECT mem res+20 0xfffffffc
# EXPECT mem res+24 14
# EXPECT mem res+28 2
# EXPECT mem res+32 -49
        .data
res:    .space 40
        .text
main:   la    $s0, res
        li    $t0, -7
        li    $t1, 3
        mult  $t0, $t1
        mflo  $t2
        mfhi  $t3
        sw    $t2, 0($s0)
        sw    $t3, 4($s0)
        div   $t0, $t1
        mflo  $t2
        mfhi  $t3
        sw    $t2, 8($s0)
        sw    $t3, 12($s0)
        li    $t4, 0x7fffffff
        li    $t5, 4
        multu $t4, $t5
        mfhi  $t2
        mflo  $t3
        sw    $t2, 16($s0)
        sw    $t3, 20($s0)
        li    $t6, 100
        li    $t7, 7
        divu  $t6, $t7
        mflo  $t2
        mfhi  $t3
        sw    $t2, 24($s0)
        sw    $t3, 28($s0)
        mul   $t8, $t0, $t7
        sw    $t8, 32($s0)
        li    $v0, 10
        syscall
