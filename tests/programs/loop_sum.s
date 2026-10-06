# Sum of 1..100.
# EXPECT status halt
# EXPECT mem result 5050
        .data
result: .word 0
        .text
main:   li    $t0, 0
        li    $t1, 1
        li    $t2, 100
loop:   addu  $t0, $t0, $t1
        addiu $t1, $t1, 1
        ble   $t1, $t2, loop
        la    $t3, result
        sw    $t0, 0($t3)
        li    $v0, 10
        syscall
