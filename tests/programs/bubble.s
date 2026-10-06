# Bubble sort of 16 signed words.
# EXPECT status halt
# EXPECT mem array+0 -40
# EXPECT mem array+4 -7
# EXPECT mem array+8 -3
# EXPECT mem array+12 0
# EXPECT mem array+16 2
# EXPECT mem array+20 5
# EXPECT mem array+24 7
# EXPECT mem array+28 12
# EXPECT mem array+32 16
# EXPECT mem array+36 19
# EXPECT mem array+40 23
# EXPECT mem array+44 34
# EXPECT mem array+48 45
# EXPECT mem array+52 61
# EXPECT mem array+56 88
# EXPECT mem array+60 99
        .data
array:  .word 34, -7, 19, 0, 88, 5, -40, 23, 7, 61, 12, -3, 45, 2, 99, 16
        .text
main:   la    $s0, array
        li    $s1, 16
        addiu $t9, $s1, -1
outer:  blez  $t9, done
        move  $t0, $s0
        move  $t1, $t9
        li    $t8, 0
inner:  lw    $t2, 0($t0)
        lw    $t3, 4($t0)
        ble   $t2, $t3, noswap
        sw    $t3, 0($t0)
        sw    $t2, 4($t0)
        li    $t8, 1
noswap: addiu $t0, $t0, 4
        addiu $t1, $t1, -1
        bgtz  $t1, inner
        addiu $t9, $t9, -1
        bnez  $t8, outer
done:   li    $v0, 10
        syscall
