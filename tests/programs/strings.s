# strlen and string reversal with byte loads and stores.
# EXPECT status halt
# EXPECT mem len 13
# EXPECT mem out+0 0x726c6421
# EXPECT mem out+4 0x2c20776f
# EXPECT mem out+8 0x656c6c6f
# EXPECT mem out+12 0x00000048
        .data
str:    .asciiz "Hello, world!"
        .align 2
len:    .word 0
out:    .space 16
        .text
main:   la    $a0, str
        li    $t0, 0
strlen: addu  $t1, $a0, $t0
        lb    $t2, 0($t1)
        beqz  $t2, endlen
        addiu $t0, $t0, 1
        b     strlen
endlen: la    $t3, len
        sw    $t0, 0($t3)
        la    $t4, out
        move  $t5, $t0
rev:    blez  $t5, finish
        addiu $t5, $t5, -1
        addu  $t1, $a0, $t5
        lbu   $t2, 0($t1)
        sb    $t2, 0($t4)
        addiu $t4, $t4, 1
        b     rev
finish: li    $v0, 10
        syscall
