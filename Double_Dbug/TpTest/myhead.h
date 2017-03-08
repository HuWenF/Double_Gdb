#include <ntddk.h>
#include <ntimage.h>
#include "LDasm.h"

#define dprintf				DbgPrint
typedef unsigned char       BYTE;
typedef BYTE				*PBYTE;
#define kmalloc(_s)	ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')

#define	DEVICE_NAME			L"\\Device\\Demo"
#define LINK_NAME			L"\\DosDevices\\Demo"
#define LINK_GLOBAL_NAME	L"\\DosDevices\\Global\\Demo"

#define IOCTL_ULR3IN 	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) //In LONG
#define IOCTL_USR3IN 	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) //In BSTR
#define IOCTL_GetKPEB 	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) //Out LONG
#define IOCTL_GetBSTR 	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS) //Out BSTR
#define IOCTL_ReInline	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS) //Test Call Only
#define IOCTL_Struct	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS) //I+O Struct



static KIRQL OldIrql;

VOID WpOffAndToDpcLevel()
{
	OldIrql = KeRaiseIrqlToDpcLevel();
	__asm
	{
		cli
			push eax
			mov eax, cr0
			and eax, 0FFFEFFFFh
			mov cr0, eax
			pop eax
	}
}

VOID WpOn()
{
	__asm
	{
		push eax
			mov eax, cr0
			or eax, 10000h
			mov cr0, eax
			pop eax
			sti
	}
	KeLowerIrql(OldIrql);
}

NTSTATUS ReadKernelMemory(PVOID Address, ULONG Size, PVOID OutBuffer)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PMDL  pMdl = 0;
	PVOID pAddress = 0;
	if (!Address) return st;
	pMdl = IoAllocateMdl(Address, Size, FALSE, FALSE, 0);
	if (pMdl)
	{
		MmBuildMdlForNonPagedPool(pMdl);
		pAddress = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
		if (pAddress)
		{
			__try
			{
				RtlCopyMemory(OutBuffer, pAddress, Size);
				st = STATUS_SUCCESS;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		}
		IoFreeMdl(pMdl);
	}
	return st;
}

NTSTATUS WriteKernelMemory(PVOID Address, ULONG Size, PVOID InBuffer)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PMDL  pMdl = 0;
	PVOID pAddress = 0;
	KSPIN_LOCK spinlock;
	KIRQL oldirql;
	if (!Address) return st;
	pMdl = IoAllocateMdl(Address, Size, FALSE, FALSE, 0);
	if (pMdl)
	{
		MmBuildMdlForNonPagedPool(pMdl);
		pAddress = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
		if (pAddress)
		{
			__try
			{
				KeInitializeSpinLock(&spinlock);
				KeAcquireSpinLock(&spinlock, &oldirql);
				WpOffAndToDpcLevel();
				RtlCopyMemory(pAddress, InBuffer, Size);
				WpOn();
				KeReleaseSpinLock(&spinlock, oldirql);
				st = STATUS_SUCCESS;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		}
		IoFreeMdl(pMdl);
	}
	return st;
}

void Hook(PVOID Func, PVOID New_Func, PVOID Proxy_Func)
{
	ULONG PatchSize;
	BYTE g_HookCode[5] = { 0xE9, 0, 0, 0, 0 };//相对跳转
	BYTE Jmp_Orig_Code[7] = { 0xEA, 0, 0, 0, 0, 0x08, 0x00 }; //绝对地址跳转
	PatchSize = GetPatchSize(Func, 5);//获得要Patch的字节数 
	//构造Proxy_Func
	memcpy((PBYTE)Proxy_Func, (PBYTE)Func, PatchSize);//实现原函数头
	*((PULONG)(Jmp_Orig_Code + 1)) = (ULONG)((PBYTE)Func + PatchSize);//原函数+N 地址
	memcpy((PBYTE)Proxy_Func + PatchSize, Jmp_Orig_Code, 7);//绝对地址跳转
	*((ULONG*)(g_HookCode + 1)) = (ULONG)New_Func - (ULONG)Func - 5;//计算JMP 地址
	WriteKernelMemory(Func, 5, g_HookCode);
}

//UnHook函数
void UnHook(PVOID Func, PVOID Proxy_Func)
{
	WriteKernelMemory(Func, 5, Proxy_Func);
}

PVOID GetFunctionAddr(PCWSTR FunctionName)
{
	UNICODE_STRING UniCodeFunctionName;
	RtlInitUnicodeString(&UniCodeFunctionName, FunctionName);
	return MmGetSystemRoutineAddress(&UniCodeFunctionName);
}



void WPOFF()
{
	//选择性编译，是给编译器看的
#if (defined(_M_AMD64) || defined(_M_IA64)) && !defined(_REALLY_GET_CALLERS_CALLER_)
	_disable();
	__writecr0(__readcr0() & (~(0x10000)));
#else
	__asm
	{
		CLI;
		MOV    EAX, CR0;
		AND EAX, NOT 10000H;
		MOV    CR0, EAX;
	}
#endif
}
void WPON()
{
#if (defined(_M_AMD64) || defined(_M_IA64)) && !defined(_REALLY_GET_CALLERS_CALLER_)
	__writecr0(__readcr0() ^ 0x10000);
	_enable();
#else
	__asm
	{
		MOV    EAX, CR0;
		OR    EAX, 10000H;
		MOV    CR0, EAX;
		STI;
	}
#endif
}