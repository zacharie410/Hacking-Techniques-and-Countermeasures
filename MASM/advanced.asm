.386
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib

.DATA
code db 0B4h, 4Ch, 4F7h, 045h, 9h, 02Bh, 02Fh, 5Bh, 56h, 51h, 89h, E5h

.CODE
start:
  ; Decrypt the code
  mov ecx, OFFSET code
  mov edx, OFFSET code
  mov al, [edx]
  xor al, [edx+1]
  xor al, [edx+2]
  xor al, [edx+3]
  xor al, [edx+4]
  xor al, [edx+5]
  xor al, [edx+6]
  xor al, [edx+7]
  xor al, [edx+8]
  xor al, [edx+9]
  xor al, [edx+10]
  mov [ecx], al

  ; Add a random jump
  jmp @F
  db 4Ch, 4F7h, 0E9h

  ; Insert code here to confuse analysis

  ; Jump back to the start of the code
  @@:
  jmp start

END start