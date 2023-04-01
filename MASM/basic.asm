.code
    start:
        jmp short call_hook

        ; Insert code to be obfuscated here
        db "Hello, World!", 0

    call_hook:
        pop eax
        add eax, 0x05
        jmp eax
.end start