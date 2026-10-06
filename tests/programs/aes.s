# aesenc / aesdec on the FIPS-197 Appendix C.1 vector (k_data is the C.1 key).
# EXPECT status halt
# EXPECT mem ct+0 0x69c4e0d8
# EXPECT mem ct+4 0x6a7b0430
# EXPECT mem ct+8 0xd8cdb780
# EXPECT mem ct+12 0x70b4c55a
# EXPECT mem back+0 0x00112233
# EXPECT mem back+4 0x44556677
# EXPECT mem back+8 0x8899aabb
# EXPECT mem back+12 0xccddeeff
# EXPECT reg $t3 0x69c4e0d8
        .data
pt:     .word 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff
ct:     .space 16
back:   .space 16
        .text
main:   la     $t0, pt
        la     $t1, ct
        la     $t2, back
        aesenc $t1, $t0
        aesdec $t2, $t1
        lw     $t3, 0($t1)
        li     $v0, 10
        syscall
