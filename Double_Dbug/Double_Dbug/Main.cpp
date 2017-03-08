
#include "codemsg.h"


extern "C" PVOID  KdEnteredDebugger;
PVOID      GetKdEnteredDebuggerAddr()
{
	return KdEnteredDebugger;
}


//获得KdEnteredDebugger 的地址
DWORD32 *EnterAddr = NULL;



//卸载驱动
VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	if (!(*KdDebuggerEnabled))
	{
		*KdDebuggerEnabled = 1;
	}

	//还原KdDebuggerNotPresent   Debug 模式为False
	if (*KdDebuggerNotPresent)
	{
		*KdDebuggerNotPresent = 0; //还原为Debug模式
	}
	//还原KdEnteredDebugger
	
	if (!(*EnterAddr))
	{
		*EnterAddr = 1; //还原为Debug模式
	}

	DbgPrint("卸载流程执行成功!");

}






// 驱动入口
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	//驱动通讯例程填写卸载驱动
	pDriverObject->DriverUnload = DriverUnload;
	
	//1获取KdEnteredDebugger
	EnterAddr = (DWORD32 *)GetKdEnteredDebuggerAddr();
	//调用API打印
	DbgPrint("Value :%x\n", (int)(*EnterAddr));
	//直接修改KdEnteredDebugger
	if (*EnterAddr)
	{
		*EnterAddr = 0;
	}
	 
	
	//开始修改Dbg标记位置
	//2修改KdDebuggerEnabled 标志为False
	if (*KdDebuggerEnabled)
	{
		*KdDebuggerEnabled = 0;//修改为普通模式
	}
	//3验证KdDebuggerNotPresent   Debug 为False
	if (!(*KdDebuggerNotPresent))
	{
		*KdDebuggerNotPresent = 1; //修改为普通模式
	}
	
	
		

	

	return STATUS_SUCCESS;



}



















