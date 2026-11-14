mov64 r1, 0
call get_arg
mov64x r1, r0
call safe_read_u8
jgt r0, 7, +2
mov64 r0, pass
exit
mov64 r0, block
exit
