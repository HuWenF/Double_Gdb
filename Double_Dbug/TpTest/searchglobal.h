//1. KeUpdateSystemTime
//
//nt!KeUpdateSystemTime + 0x417:
//84096d65 33c9            xor     ecx, ecx
//84096d67 8d542420        lea     edx, [esp + 20h]
//
//nt!KeUpdateSystemTime + 0x41d :
//84096d6b 803d2c1d188400  cmp     byte ptr[nt!KdDebuggerEnabled(84181d2c)], 0		<--ul_KdDebuggerEnabled_1
//84096d72 7464            je      nt!KeUpdateSystemTime + 0x48a (84096dd8)
//
//
//2. KeUpdateRunTime
//
//nt!KeUpdateRunTime + 0x149:
//840970c2 803d2c1d188400  cmp     byte ptr[nt!KdDebuggerEnabled(84181d2c)], 0		<--ul_KdDebuggerEnabled_2
//840970c9 7412            je      nt!KeUpdateRunTime + 0x164 (840970dd)
//
//3. KdCheckForDebugBreak
//
//kd > uf kdcheckfordebugbreak
//nt!KdCheckForDebugBreak:
//840970e9 803d275d148400  cmp     byte ptr[nt!KdPitchDebugger(84145d27)], 0		<--ul_KdPitchDebugger_1
//840970f0 7519            jne     nt!KdCheckForDebugBreak + 0x22 (8409710b)
//
//nt!KdCheckForDebugBreak + 0x9 :
//840970f2 803d2c1d188400  cmp     byte ptr[nt!KdDebuggerEnabled(84181d2c)], 0		<--ul_KdDebuggerEnabled_3
//840970f9 7410            je      nt!KdCheckForDebugBreak + 0x22 (8409710b)
//
//
//4. KdPollBreakIn
//
//kd > uf KdPollBreakIn
//nt!KdPollBreakIn:
//8409711f 8bff            mov     edi, edi
//84097121 55              push    ebp
//84097122 8bec            mov     ebp, esp
//84097124 51              push    ecx
//84097125 53              push    ebx
//84097126 33db            xor     ebx, ebx
//84097128 381d275d1484    cmp     byte ptr[nt!KdPitchDebugger(84145d27)], bl		<--ul_KdPitchDebugger_2
//8409712e 7407            je      nt!KdPollBreakIn + 0x18 (84097137)
//
//nt!KdPollBreakIn + 0x11:
//84097130 32c0            xor     al, al
//84097132 e9d2000000      jmp     nt!KdPollBreakIn + 0xea (84097209)
//
//nt!KdPollBreakIn + 0x18 :
//84097137 885dff          mov     byte ptr[ebp - 1], bl
//8409713a 381d2c1d1884    cmp     byte ptr[nt!KdDebuggerEnabled(84181d2c)], bl		<--ul_KdDebuggerEnabled_4
//84097140 0f84c0000000    je      nt!KdPollBreakIn + 0xe7 (84097206)

#include "myhead.h"
#include "func.h"

ULONG_PTR ul_KeUpdateSystemTimeAssist;
ULONG_PTR ul_KeUpdateSystemTime;

ULONG_PTR ul_KeUpdateRunTime;

ULONG_PTR ul_KdCheckForDebugBreak;

ULONG_PTR ul_KdPollBreakIn;

// 这里顺序按照上面注释的顺序来
ULONG_PTR ul_KdDebuggerEnabled_1;
ULONG_PTR ul_KdDebuggerEnabled_2;
ULONG_PTR ul_KdDebuggerEnabled_3;
ULONG_PTR ul_KdDebuggerEnabled_4;


ULONG_PTR ul_KdPitchDebugger_1;
ULONG_PTR ul_KdPitchDebugger_2;


// 用来保存原来内核变量地址
ULONG_PTR ul_oldKdDebuggerEnabled;
ULONG_PTR ul_oldKdPitchDebugger;

// 自己定义的全局变量
BOOLEAN bool_myKdDebuggerEnabled = TRUE;
BOOLEAN bool_myKdPitchDebugger = FALSE;





ULONG_PTR GetKeUpdateSystemTimeAddr()
{
	PUCHAR pStart = (PUCHAR)ul_KeUpdateSystemTimeAssist;
	ULONG_PTR retAddress;
	for (ULONG i = 0; i < 100; i++)
	{
		if (*(pStart + i) == 0xe8 &&
			*(pStart + i + 5) == 0xfa)
		{
			retAddress = *(ULONG_PTR*)(pStart + i + 1) + (ULONG_PTR)(pStart + i) + 5;
			return retAddress;
		}
	}
	return 0;
}


ULONG_PTR GetKdCheckForDebugBreak()
{
	PUCHAR pStart = (PUCHAR)ul_KeUpdateRunTime;
	ULONG_PTR retAddress;
	for (ULONG i = 0x100; i < 0x200; i++)
	{
		if (*(pStart + i) == 0xe8 &&
			*(pStart + i + 5) == 0x5f)
		{
			retAddress = *(ULONG_PTR*)(pStart + i + 1) + (ULONG_PTR)(pStart + i) + 5;
			return retAddress;
		}
	}
	return 0;
}


ULONG_PTR GetKdDebuggerEnabled_1()
{
	PUCHAR pStart = (PUCHAR)ul_KeUpdateSystemTime;
	ULONG_PTR retAddress;
	for (ULONG i = 0x400; i < 0x500; i++)
	{
		if (*(pStart + i) == 0x80 &&
			*(pStart + i + 1) == 0x3d &&
			*(pStart + i + 7) == 0x74 &&
			*(pStart + i + 8) == 0x64)
		{
			retAddress = (ULONG_PTR)(pStart + i + 2);
			return retAddress;
		}
	}
	return 0;
}


ULONG_PTR GetKdDebuggerEnabled_2()
{
	PUCHAR pStart = (PUCHAR)ul_KeUpdateRunTime;
	ULONG_PTR retAddress;
	for (ULONG i = 0x100; i < 0x200; i++)
	{
		if (*(pStart + i) == 0x80 &&
			*(pStart + i + 1) == 0x3d &&
			*(pStart + i + 7) == 0x74 &&
			*(pStart + i + 8) == 0x12)
		{
			retAddress = (ULONG_PTR)(pStart + i + 2);
			return retAddress;
		}
	}
	return 0;
}

ULONG_PTR GetKdDebuggerEnabled_3()
{
	PUCHAR pStart = (PUCHAR)ul_KdCheckForDebugBreak;
	ULONG_PTR retAddress;
	for (ULONG i = 0; i < 100; i++)
	{
		if (*(pStart + i) == 0x80 &&
			*(pStart + i + 1) == 0x3d &&
			*(pStart + i + 7) == 0x74 &&
			*(pStart + i + 8) == 0x10)
		{
			retAddress = (ULONG_PTR)(pStart + i + 2);
			return retAddress;
		}
	}
	return 0;
}


ULONG_PTR GetKdDebuggerEnabled_4()
{
	PUCHAR pStart = (PUCHAR)ul_KdPollBreakIn;
	ULONG_PTR retAddress;
	for (ULONG i = 0; i < 50; i++)
	{
		if (*(pStart + i) == 0x38 &&
			*(pStart + i + 1) == 0x1d &&
			*(pStart + i + 6) == 0x0f &&
			*(pStart + i + 7) == 0x84)
		{
			retAddress = (ULONG_PTR)(pStart + i + 2);
			return retAddress;
		}
	}
	return 0;
}

ULONG_PTR GetKdPitchDebugger_1()
{
	PUCHAR pStart = (PUCHAR)ul_KdCheckForDebugBreak;
	ULONG_PTR retAddress;
	for (ULONG i = 0; i < 100; i++)
	{
		if (*(pStart + i) == 0x80 &&
			*(pStart + i + 1) == 0x3d &&
			*(pStart + i + 7) == 0x75 &&
			*(pStart + i + 8) == 0x19)
		{
			retAddress = (ULONG_PTR)(pStart + i + 2);
			return retAddress;
		}
	}
	return 0;
}


ULONG_PTR GetKdPitchDebugger_2()
{
	PUCHAR pStart = (PUCHAR)ul_KdPollBreakIn;
	ULONG_PTR retAddress;
	for (ULONG i = 0; i < 100; i++)
	{
		if (*(pStart + i) == 0x38 &&
			*(pStart + i + 1) == 0x1d &&
			*(pStart + i + 6) == 0x74 &&
			*(pStart + i + 7) == 0x07)
		{
			retAddress = (ULONG_PTR)(pStart + i + 2);
			return retAddress;
		}
	}
	return 0;
}


// 转移内核变量函数
void MoveGlobal()
{
	ul_KeUpdateSystemTimeAssist = (ULONG_PTR)GetFuncAddress(L"KeUpdateSystemTime");
	ul_KeUpdateSystemTime = GetKeUpdateSystemTimeAddr();
	ul_KdDebuggerEnabled_1 = GetKdDebuggerEnabled_1();

	ul_KeUpdateRunTime = (ULONG_PTR)GetFuncAddress(L"KeUpdateRunTime");
	ul_KdDebuggerEnabled_2 = GetKdDebuggerEnabled_2();


	ul_KdCheckForDebugBreak = GetKdCheckForDebugBreak();

	ul_KdDebuggerEnabled_3 = GetKdDebuggerEnabled_3();
	ul_KdPitchDebugger_1 = GetKdPitchDebugger_1();


	ul_KdPollBreakIn = (ULONG_PTR)GetFuncAddress(L"KdPollBreakIn");
	ul_KdDebuggerEnabled_4 = GetKdDebuggerEnabled_4();

	ul_KdPitchDebugger_2 = GetKdPitchDebugger_2();

	// 保存原始内核变量
	ul_oldKdDebuggerEnabled = *(ULONG_PTR*)ul_KdDebuggerEnabled_1;
	ul_oldKdPitchDebugger = *(ULONG_PTR*)ul_KdPitchDebugger_1;

	WPOFF();
	// 开始转移内核变量
	*(ULONG_PTR*)ul_KdDebuggerEnabled_1 = (ULONG_PTR)&bool_myKdDebuggerEnabled;
	*(ULONG_PTR*)ul_KdDebuggerEnabled_2 = (ULONG_PTR)&bool_myKdDebuggerEnabled;
	*(ULONG_PTR*)ul_KdDebuggerEnabled_3 = (ULONG_PTR)&bool_myKdDebuggerEnabled;
	*(ULONG_PTR*)ul_KdDebuggerEnabled_4 = (ULONG_PTR)&bool_myKdDebuggerEnabled;
	*(ULONG_PTR*)ul_KdPitchDebugger_1 = (ULONG_PTR)&bool_myKdPitchDebugger;
	*(ULONG_PTR*)ul_KdPitchDebugger_2 = (ULONG_PTR)&bool_myKdPitchDebugger;
	WPON();


	DbgPrint("内核变量转移完成\n");

}

// 恢复转移的内核变量
void RecoverGlobal()
{
	// 恢复原来内核变量
	WPOFF();
	*(ULONG_PTR*)ul_KdDebuggerEnabled_1 = ul_oldKdDebuggerEnabled;
	*(ULONG_PTR*)ul_KdDebuggerEnabled_2 = ul_oldKdDebuggerEnabled;
	*(ULONG_PTR*)ul_KdDebuggerEnabled_3 = ul_oldKdDebuggerEnabled;
	*(ULONG_PTR*)ul_KdDebuggerEnabled_4 = ul_oldKdDebuggerEnabled;
	*(ULONG_PTR*)ul_KdPitchDebugger_1 = ul_oldKdPitchDebugger;
	*(ULONG_PTR*)ul_KdPitchDebugger_2 = ul_oldKdPitchDebugger;
	WPON();
	DbgPrint("内核变量恢复完成\n");
}



#pragma LOCKEDCODE
NTSTATUS FindKrlModule(ULONG *ulSysModuleBase, ULONG *ulSize)
{
	ULONG uRtnLength;
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PVOID pBuffer = NULL;
	SYSTEM_MODULE_INFORMATION KrlModInfo;
	char* ImageName = NULL;
	PMODULES pKrlList = NULL;
	ULONG uModuleCounts = 0;

	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &uRtnLength);
	if (!uRtnLength)
	{
		DbgPrint("Get SystemModuleInfo Length error,%d,%p\n", uRtnLength, st);
		return st;
	}

	pBuffer = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, uRtnLength);
	if (pBuffer == NULL)
	{
		DbgPrint("ExAllocatePool error\n");
		return st;
	}

	st = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, uRtnLength, 0);
	if (!NT_SUCCESS(st))
	{
		DbgPrint("ZwQuerySystemInformation error\n");
		return st;
	}

	pKrlList = (PMODULES)pBuffer;

	uModuleCounts = pKrlList->ulCount;

	for (ULONG i = 0; i < uModuleCounts; i++)
	{
		KrlModInfo = pKrlList->smi[i];
		ImageName = KrlModInfo.ImageName;
		if (strstr(ImageName, "kdcom.dll"))
		{
			*ulSysModuleBase = KrlModInfo.Base;
			*ulSize = KrlModInfo.Size;
			break;
		}
	}

	return st;
}


BOOLEAN GetKdReceiveSendPacketAddress(ULONG_PTR ulModuleBase, ULONG_PTR *ul_receive_addr, ULONG_PTR *ul_send_addr)
{

	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS NtDllHeader;
	IMAGE_OPTIONAL_HEADER opthdr;
	ULONG_PTR* arrayOfFunctionAddresses;
	ULONG_PTR* arrayOfFunctionNames;
	SHORT* arrayOfFunctionOrdinals;
	ULONG_PTR functionOrdinal;
	ULONG_PTR Base, x, functionAddress, ulOldAddress;
	IMAGE_EXPORT_DIRECTORY *pExportTable;
	char *functionName;

	__try
	{
		pDosHeader = (PIMAGE_DOS_HEADER)ulModuleBase;
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			KdPrint(("failed to find NtHeader\r\n"));
			return FALSE;
		}
		NtDllHeader = (PIMAGE_NT_HEADERS)(ULONG_PTR)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
		if (NtDllHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			KdPrint(("failed to find NtHeader\r\n"));
			return FALSE;
		}
		opthdr = NtDllHeader->OptionalHeader;
		pExportTable = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ulModuleBase + opthdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); //得到导出表
		arrayOfFunctionAddresses = (ULONG_PTR*)((BYTE*)ulModuleBase + pExportTable->AddressOfFunctions);  //地址表
		arrayOfFunctionNames = (ULONG_PTR*)((BYTE*)ulModuleBase + pExportTable->AddressOfNames);         //函数名表
		arrayOfFunctionOrdinals = (SHORT*)((BYTE*)ulModuleBase + pExportTable->AddressOfNameOrdinals);

		Base = pExportTable->Base;

		for (x = 0; x < pExportTable->NumberOfFunctions; x++) //在整个导出表里扫描
		{
			functionName = (char*)((BYTE*)ulModuleBase + arrayOfFunctionNames[x]);
			functionOrdinal = arrayOfFunctionOrdinals[x] + Base - 1;
			functionAddress = (ULONG_PTR)((BYTE*)ulModuleBase + arrayOfFunctionAddresses[functionOrdinal]);

			if (_stricmp(functionName, "KdReceivePacket") == 0)
			{
				KdPrint(("%08x:%s\r\n", functionAddress, functionName));

				*ul_receive_addr = functionAddress;
			}
			if (_stricmp(functionName, "KdSendPacket") == 0)
			{
				KdPrint(("%08x:%s\r\n", functionAddress, functionName));

				*ul_send_addr = functionAddress;
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER){

	}
	return FALSE;
}



void PatchSendReceivePacket()
{
	// patch KdSendPacket KdReceivePacket
	FindKrlModule(&ul_kdcom_base, &ul_kdcom_size);
	////我们通过扫描kdcom.dll的导出表，得到两个串口发送函数的地址
	GetKdReceiveSendPacketAddress(ul_kdcom_base, &ul_KdReceivePacket, &ul_KdSendPacket);

	//DbgPrint("ul_kdcom_base:%p\n", ul_kdcom_base);
	//DbgPrint("ul_kdcom_size:%p\n", ul_kdcom_size);
	//DbgPrint("ul_KdReceivePacket:%p\n", ul_KdReceivePacket);
	//DbgPrint("ul_KdSendPacket:%p\n", ul_KdSendPacket);

	ul_my_KdSendPacket = &ul_KdSendPacket;
	ul_my_KdReceivePacket = &ul_KdReceivePacket;

	//DbgPrint("ul_my_KdSendPacket:%p\n", ul_my_KdSendPacket);
	//DbgPrint("ul_my_KdReceivePacket:%p\n", ul_my_KdReceivePacket);

	ul_imp_KdSendPacket = (ULONG_PTR)GetFuncAddress(L"KdRefreshDebuggerNotPresent") - 0xB;
	ul_imp_KdReceivePacket = (ULONG_PTR)GetFuncAddress(L"IoAcquireRemoveLockEx") - 0xB;

	//DbgPrint("ul_imp_KdSendPacket:%p\n", ul_imp_KdSendPacket);
	//DbgPrint("ul_imp_KdReceivePacket:%p\n", ul_imp_KdReceivePacket);

	ul_edit_send = (ULONG_PTR*)(ul_imp_KdSendPacket + 2);
	ul_edit_receive = (ULONG_PTR*)(ul_imp_KdReceivePacket + 2);
	ul_oldimp_KdSendPacket = *ul_edit_send;
	ul_oldimp_KdReceivePacket = *ul_edit_receive;

	//DbgPrint("ul_edit_send:%p\n", ul_edit_send);
	//DbgPrint("ul_edit_receive:%p\n", ul_edit_receive);

	WPOFF();
	*ul_edit_send = (ULONG_PTR)ul_my_KdSendPacket;
	*ul_edit_receive = (ULONG_PTR)ul_my_KdReceivePacket;
	WPON();
	DbgPrint("KdSendPacket, KdReceivePacket：处理成功\n");
}


