
#include "codemsg.h"







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





NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	DbgPrint("Enter DispatchCreate.\n");

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	DbgPrint("End DispatchCreate.\n");
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);

	DbgPrint("Enter DispatchClose.\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	//完成Irp连接
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	DbgPrint("End DispatchClose.\n");
	return STATUS_SUCCESS;
}



// 驱动入口
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	//驱动通讯例程填写卸载驱动
	pDriverObject->DriverUnload = DriverUnload;

	RTL_OSVERSIONINFOW	osi;
	//UNREFERENCED_PARAMETER 的作用就是忽视这个参数就算在没有使用的情况下，是礼仪
	UNREFERENCED_PARAMETER(osi);
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);

	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName;
	UNICODE_STRING ustrDevName;
	PDEVICE_OBJECT pDevObj;
	DbgPrint("Enter DriverEntry.\n");
	//配置好分发函数
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObject->DriverUnload = DriverUnload;

	//拷贝设备名字字符串
	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	//创建一个设备
	status = IoCreateDevice(pDriverObject, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))	return status;

	//判断WDM版本是否可用
	if (IoIsWdmVersionAvailable(1, 0x10))
		RtlInitUnicodeString(&ustrLinkName, LINK_GLOBAL_NAME);
	else
		RtlInitUnicodeString(&ustrLinkName, LINK_NAME);
	//创建符号连接
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		//如果失败了删除创建的设备
		IoDeleteDevice(pDevObj);
		return status;
	}
	DbgPrint("End DriverEntry.\n");

	//接下来开始改变全局变量地址
	MoveGlobleValue();

	
	
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



















