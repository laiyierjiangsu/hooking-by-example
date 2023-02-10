.DATA

msgCaption  DB "Message box text",0

.CODE
ALIGN 16

EXTERN GetMsgBoxType : PROC
; EXTERN MessageBoxA : PROC
EXTERN __imp_MessageBoxA : qword

EXTERN payload : PROC


asm_func PROC
	; RCX = address for the string for the message box
	sub		rsp, 28h		; shadow stack
	mov		[rsp], rcx

	call	GetMsgBoxType

	mov		r9, rax
	mov		r8, [rsp]
	lea		rdx, [msgCaption]
	xor		ecx, ecx

	call	[__imp_MessageBoxA]

	add		rsp, 28h		; restoring shadow stack
	ret
asm_func ENDP

asm_payload PROC
	sub		rsp, 28h		; shadow stack
	mov		[rsp], rcx
	jmp payload
	;跳转到返回地址
	add		rsp, 28h		; restoring shadow stack
	ret
asm_payload ENDP
END