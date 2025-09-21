.data
# ------------- Instruction Blocks ---------------------

# Block 0
instr0_NOP:     .word 0x00000000        # NOP
instr1_ADD:     .word 0x00430820        # ADD $1, $2, $3
instr2_SUB:     .word 0x00431022        # SUB $2, $2, $3
instr3_AND:     .word 0x00431824        # AND $3, $2, $3

# Block 1
instr4_OR:      .word 0x00432025        # OR $4, $2, $3
instr5_XOR:     .word 0x00432826        # XOR $5, $2, $3
instr6_SLL:     .word 0x00023080        # SLL $6, $2, 2
instr7_SRL:     .word 0x00023882        # SRL $7, $2, 2

# Block 2
instr8_MULT:    .word 0x00433018        # MULT $2, $3
instr9_LW:      .word 0x8C480010        # LW $8, 16($2)
instr10_SW:     .word 0xAC490014        # SW $9, 20($2)
instr11_BEQ:    .word 0x10430004        # BEQ $2, $3, offset=4

# Block 3
instr12_BNE:    .word 0x14430004        # BNE $2, $3, offset=4
instr13_J:      .word 0x08000020        # J to address 0x20
instr14_AESENC: .word 0x14020000        # AES_ENC (opcode 5)
instr15_AESDEC: .word 0x18020000        # AES_DEC (opcode 6)

# ------------ Memory for instructions ---------------
prog_mem: .space 64

# ------------ Space for test data -------------------
test_data: .word 0x00000001, 0x00000002, 0x00000003, 0x00000004
result_data: .space 16

# ------------ Space for signature -------------------
signature: .word 0

.text
.globl main
main:
    # Load base address of prog_mem
    la $t0, prog_mem

    # ====== Load all instructions into prog_mem ======
    # Block 0
    la $t1, instr0_NOP
    lw $t2, 0($t1)
    sw $t2, 0($t0)

    la $t1, instr1_ADD
    lw $t2, 0($t1)
    sw $t2, 4($t0)

    la $t1, instr2_SUB
    lw $t2, 0($t1)
    sw $t2, 8($t0)

    la $t1, instr3_AND
    lw $t2, 0($t1)
    sw $t2, 12($t0)

    # Block 1
    la $t1, instr4_OR
    lw $t2, 0($t1)
    sw $t2, 16($t0)

    la $t1, instr5_XOR
    lw $t2, 0($t1)
    sw $t2, 20($t0)

    la $t1, instr6_SLL
    lw $t2, 0($t1)
    sw $t2, 24($t0)

    la $t1, instr7_SRL
    lw $t2, 0($t1)
    sw $t2, 28($t0)

    # Block 2
    la $t1, instr8_MULT
    lw $t2, 0($t1)
    sw $t2, 32($t0)

    la $t1, instr9_LW
    lw $t2, 0($t1)
    sw $t2, 36($t0)

    la $t1, instr10_SW
    lw $t2, 0($t1)
    sw $t2, 40($t0)

    la $t1, instr11_BEQ
    lw $t2, 0($t1)
    sw $t2, 44($t0)

    # Block 3
    la $t1, instr12_BNE
    lw $t2, 0($t1)
    sw $t2, 48($t0)

    la $t1, instr13_J
    lw $t2, 0($t1)
    sw $t2, 52($t0)

    la $t1, instr14_AESENC
    lw $t2, 0($t1)
    sw $t2, 56($t0)

    la $t1, instr15_AESDEC
    lw $t2, 0($t1)
    sw $t2, 60($t0)

    # ====== Dummy register values for testing ======
    addi $2, $0, 1
    addi $3, $0, 2
    addi $4, $0, 3
    addi $5, $0, 4
    addi $6, $0, 5
    addi $7, $0, 6

    # ====== Compute "signature" for validation ======
    add $8, $2, $3
    add $8, $8, $4
    add $8, $8, $5
    add $8, $8, $6
    add $8, $8, $7

    # Store signature result
    la $9, signature
    sw $8, 0($9)

    # ====== Infinite loop at end ======
end:
    j end
