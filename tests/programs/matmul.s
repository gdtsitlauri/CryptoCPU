# 4x4 integer matrix multiply C = A * B.
# EXPECT status halt
# EXPECT mem C+0 20
# EXPECT mem C+4 11
# EXPECT mem C+8 12
# EXPECT mem C+12 14
# EXPECT mem C+16 48
# EXPECT mem C+20 27
# EXPECT mem C+24 28
# EXPECT mem C+28 42
# EXPECT mem C+32 76
# EXPECT mem C+36 43
# EXPECT mem C+40 44
# EXPECT mem C+44 70
# EXPECT mem C+48 104
# EXPECT mem C+52 59
# EXPECT mem C+56 60
# EXPECT mem C+60 98
        .data
A:      .word 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
B:      .word 2, 0, 1, 3, 1, 1, 0, 2, 0, 3, 1, 1, 4, 0, 2, 1
C:      .space 64
        .text
main:   la    $s0, A
        la    $s1, B
        la    $s2, C
        li    $s3, 4
        li    $t0, 0              # i
iloop:  li    $t1, 0              # j
jloop:  li    $t2, 0              # k
        li    $t3, 0              # acc
kloop:  sll   $t4, $t0, 2
        addu  $t4, $t4, $t2
        sll   $t4, $t4, 2
        addu  $t4, $t4, $s0
        lw    $t5, 0($t4)         # A[i][k]
        sll   $t6, $t2, 2
        addu  $t6, $t6, $t1
        sll   $t6, $t6, 2
        addu  $t6, $t6, $s1
        lw    $t7, 0($t6)         # B[k][j]
        mul   $t8, $t5, $t7
        addu  $t3, $t3, $t8
        addiu $t2, $t2, 1
        blt   $t2, $s3, kloop
        sll   $t4, $t0, 2
        addu  $t4, $t4, $t1
        sll   $t4, $t4, 2
        addu  $t4, $t4, $s2
        sw    $t3, 0($t4)
        addiu $t1, $t1, 1
        blt   $t1, $s3, jloop
        addiu $t0, $t0, 1
        blt   $t0, $s3, iloop
        li    $v0, 10
        syscall
