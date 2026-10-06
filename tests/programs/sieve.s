# Sieve of Eratosthenes: number of primes below 200 (46).
# EXPECT status halt
# EXPECT mem count 46
        .data
count:  .word 0
flags:  .space 200
        .text
main:   la    $s0, flags
        li    $s1, 200
        li    $t0, 2
mark:   mul   $t1, $t0, $t0
        bge   $t1, $s1, countp
        addu  $t2, $s0, $t0
        lbu   $t3, 0($t2)
        bnez  $t3, nextp
inner:  bge   $t1, $s1, nextp
        addu  $t4, $s0, $t1
        li    $t5, 1
        sb    $t5, 0($t4)
        addu  $t1, $t1, $t0
        b     inner
nextp:  addiu $t0, $t0, 1
        b     mark
countp: li    $t0, 2
        li    $t6, 0
cloop:  bge   $t0, $s1, store
        addu  $t2, $s0, $t0
        lbu   $t3, 0($t2)
        bnez  $t3, cnext
        addiu $t6, $t6, 1
cnext:  addiu $t0, $t0, 1
        b     cloop
store:  la    $t7, count
        sw    $t6, 0($t7)
        li    $v0, 10
        syscall
