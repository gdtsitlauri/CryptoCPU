# The original CryptoCPU v1 demo. In v1 the value 0x15 was precomputed by MARS
# and only checked; here the processor computes it from the encrypted program.
# EXPECT status halt
# EXPECT mem signature 0x15
        .data
test_data: .word 1, 2, 3, 4
signature: .word 0
        .text
main:   addi $2, $0, 1
        addi $3, $0, 2
        addi $4, $0, 3
        addi $5, $0, 4
        addi $6, $0, 5
        addi $7, $0, 6
        add  $8, $2, $3
        add  $8, $8, $4
        add  $8, $8, $5
        add  $8, $8, $6
        add  $8, $8, $7
        la   $9, signature
        sw   $8, 0($9)
        li   $v0, 10
        syscall
