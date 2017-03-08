#include "myhead.h"



typedef unsigned char BYTE;

#define SystemModuleInformation 11

NTSTATUS __stdcall ZwQuerySystemInformation(
	ULONG_PTR SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef struct _SYSTEM_MODULE_INFORMATION  // ϵͳģ����Ϣ
{
	ULONG  Reserved[2];
	ULONG  Base;
	ULONG  Size;
	ULONG  Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR   ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _tagSysModuleList {          //ģ�����ṹ
	ULONG ulCount;
	SYSTEM_MODULE_INFORMATION smi[1];
} MODULES, *PMODULES;



#define LOCKEDCODE code_seg()   

ULONG_PTR ul_kdcom_base, ul_kdcom_size;
ULONG_PTR ul_KdReceivePacket;
ULONG_PTR ul_KdSendPacket;

ULONG_PTR* ul_my_KdSendPacket;
ULONG_PTR* ul_my_KdReceivePacket;

ULONG_PTR ul_imp_KdSendPacket;
ULONG_PTR ul_imp_KdReceivePacket;
ULONG_PTR ul_oldimp_KdSendPacket;
ULONG_PTR ul_oldimp_KdReceivePacket;

ULONG_PTR* ul_edit_send;
ULONG_PTR* ul_edit_receive;

KTIMER myTimer;
KDPC   myDpc;


ULONG_PTR ul_TP_RelBaseAddress;
BOOLEAN   bl_FirstInto_KdDsiableDebugger = FALSE;


// ����KdEnteredDebugger��ַ   ��KdEnterDebugger����������������0x89   0x35
// ���Һ�����ַ
PVOID GetFuncAddress(LPWSTR lpFuncName)
{
	PVOID pFuncName;
	UNICODE_STRING usFuncName;
	RtlInitUnicodeString(&usFuncName, lpFuncName);
	DbgPrint("%wZ\n", &usFuncName);
	pFuncName = MmGetSystemRoutineAddress(&usFuncName);

	return pFuncName;
}



// ����KdEnteredDebugger��ַ 
extern SIZE_T KdEnteredDebugger;
SIZE_T GetKdEnteredDebuggerAddr()
{
	return KdEnteredDebugger;
}


// HookIoAllocMdl
typedef PMDL(__stdcall *_MyIoAllocateMdl)(
	_In_opt_     PVOID VirtualAddress,
	_In_         ULONG Length,
	_In_         BOOLEAN SecondaryBuffer,
	_In_         BOOLEAN ChargeQuota,
	_Inout_opt_  PIRP Irp
	);

_MyIoAllocateMdl old_IoAllocateMdl;


PMDL MyIoAllocateMdl(
	__in_opt PVOID  VirtualAddress,
	__in ULONG  Length,
	__in BOOLEAN  SecondaryBuffer,
	__in BOOLEAN  ChargeQuota,
	__inout_opt PIRP  Irp  OPTIONAL)
{
	PVOID pKdEnteredDebugger = (PVOID)GetKdEnteredDebuggerAddr();
	if (pKdEnteredDebugger == VirtualAddress)
	{
		VirtualAddress = (PVOID)((SIZE_T)pKdEnteredDebugger + 0x20);  //+0x20  ����������������λ��
	}
	

	return old_IoAllocateMdl(VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp);
}




typedef NTSTATUS(*KDDISABLEDEBUGGER)(VOID);

KDDISABLEDEBUGGER old_KdDisableDebugger;

NTSTATUS MyKdDisableDebugger(VOID)
{
	if (bl_FirstInto_KdDsiableDebugger == FALSE)
	{
		// �������ʱ��EDI����� ϵͳ��KdDebuggerEnabled ֱ�ӽ�ϵͳ��д��0�ˣ�
		// ��Ϊ�ڼ���������ʱ���Ѿ�ת���ں˱����ˣ����Ժܰ�ȫ~
		ULONG_PTR ul_ret = NULL;
		__asm
		{
			push eax;
			push ebx;
			mov  eax, [ebp + 4];
			add  eax, 4;
			mov  ebx, [eax];
			mov  ul_ret, ebx;
			mov[edi], 0;
			pop  ebx;
			pop  eax;
		}
		ul_TP_RelBaseAddress = ul_ret - 0x47277;
		DbgPrint("Tp �������ص�ַ��%p\n", ul_TP_RelBaseAddress);
		// ��ֻ֤�е�һ�βŻ����
		bl_FirstInto_KdDsiableDebugger = TRUE;
		//KdBreakPoint();
		return 0;
	}
	else
	{
		//KdBreakPoint();
		return 0;
	}
}

void HookKdDisableDebugger(BOOLEAN bEnble)
{
	if (bEnble == TRUE)
	{
		old_KdDisableDebugger = kmalloc(20);
		memset(old_KdDisableDebugger, 0x90, 20);
		Hook(KdDisableDebugger, MyKdDisableDebugger, (PVOID)old_KdDisableDebugger);
		DbgPrint("KdDisableDebugger hooked...");
	}
	else
	{
		UnHook(KdDisableDebugger, old_KdDisableDebugger);
		ExFreePool(old_KdDisableDebugger);
		DbgPrint("KdDisableDebugger unhooked...");
	}
}



////////////////////////////////////////////////////////////////////////
//ģ����ػص���������
VOID LoadImageRoutine(IN PUNICODE_STRING  FullImageName,
	IN HANDLE  ProcessId, // where image is mapped
	IN PIMAGE_INFO  ImageInfo)
{
	UNREFERENCED_PARAMETER(ProcessId);
	if (wcsstr(FullImageName->Buffer, L"TesSafe.sys") != NULL)
	{
		KdPrint(("TesSafe.sys -------------����-------------\r\n"));
		KdPrint(("TesSafe.sys --->ImageBase 0x%x\r\n", (ULONG)ImageInfo->ImageBase));
		KdPrint(("TesSafe.sys --->ImageSize 0x%x\r\n", (ULONG)ImageInfo->ImageSize));
		KdPrint(("�ϵ�����: ba e 1 0x%x+ \r\n", (ULONG)ImageInfo->ImageBase));

		HookKdDisableDebugger(TRUE);

		KdBreakPoint();



	}
	return;
}


void HookIoAllocMdl(BOOLEAN bEnble)
{
	if (bEnble == TRUE)
	{
		old_IoAllocateMdl = kmalloc(20);
		memset(old_IoAllocateMdl, 0x90, 20);
		Hook(IoAllocateMdl, MyIoAllocateMdl, (PVOID)old_IoAllocateMdl);
		DbgPrint("IoAllocateMdl hooked...");
	}
	else
	{
		UnHook(IoAllocateMdl, old_IoAllocateMdl);
		ExFreePool(old_IoAllocateMdl);
		DbgPrint("IoAllocateMdl unhooked...");
	}
}


