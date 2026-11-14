# Compare argument 1 with the explicit observation in slot 0.
mov64 r1, 1
call get_arg
mov64x r6, r0
mov64 r1, 0
call get_reg
# jgt r6, r0, +2 (register comparison in the existing VM subset)
raw 0x2d, 0x06, 2, 0
mov64 r0, pass
exit
mov64 r0, block
exit
