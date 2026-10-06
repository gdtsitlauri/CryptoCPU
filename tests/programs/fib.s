# Recursive Fibonacci: calls, returns and the stack.
# EXPECT status halt
# EXPECT mem result 610
        .data
result: .word 0
        .text
main:   li    $a0, 15
        jal   fib
        la    $t0, result
        sw    $v0, 0($t0)
        li    $v0, 10
        syscall

fib:    slti  $t0, $a0, 2
        beqz  $t0, fib_rec
        move  $v0, $a0
        jr    $ra
fib_rec:
        addiu $sp, $sp, -12
        sw    $ra, 8($sp)
        sw    $a0, 4($sp)
        addiu $a0, $a0, -1
        jal   fib
        sw    $v0, 0($sp)
        lw    $a0, 4($sp)
        addiu $a0, $a0, -2
        jal   fib
        lw    $t1, 0($sp)
        addu  $v0, $v0, $t1
        lw    $ra, 8($sp)
        addiu $sp, $sp, 12
        jr    $ra
