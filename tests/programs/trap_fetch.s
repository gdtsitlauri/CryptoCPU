# Jumping outside instruction memory traps when the target reaches execute.
# EXPECT status trap-fetch
        .text
main:   li    $t0, 0x00800000
        jr    $t0
        li    $v0, 10
        syscall
