global _send_addr
global _send_trampoline@16

section .bss
	_send_addr: resb 4
	
section .text
	_send_trampoline@16:
		mov edi, edi
		push ebp
		mov ebp, esp
		
		mov eax, [_send_addr]
		add eax, 5
		jmp eax
