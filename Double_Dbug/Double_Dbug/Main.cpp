
#include "codemsg.h"







//���KdEnteredDebugger �ĵ�ַ
DWORD32 *EnterAddr = NULL;



//ж������
VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	if (!(*KdDebuggerEnabled))
	{
		*KdDebuggerEnabled = 1;
	}
	//��ԭKdDebuggerNotPresent   Debug ģʽΪFalse
	if (*KdDebuggerNotPresent)
	{
		*KdDebuggerNotPresent = 0; //��ԭΪDebugģʽ
	}
	//��ԭKdEnteredDebugger
	
	if (!(*EnterAddr))
	{
		*EnterAddr = 1; //��ԭΪDebugģʽ
	}

	DbgPrint("ж������ִ�гɹ�!");
	
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
	//���Irp����
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	DbgPrint("End DispatchClose.\n");
	return STATUS_SUCCESS;
}



// �������
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	//����ͨѶ������дж������
	pDriverObject->DriverUnload = DriverUnload;

	RTL_OSVERSIONINFOW	osi;
	//UNREFERENCED_PARAMETER �����þ��Ǻ����������������û��ʹ�õ�����£�������
	UNREFERENCED_PARAMETER(osi);
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);

	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName;
	UNICODE_STRING ustrDevName;
	PDEVICE_OBJECT pDevObj;
	DbgPrint("Enter DriverEntry.\n");
	//���ú÷ַ�����
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObject->DriverUnload = DriverUnload;

	//�����豸�����ַ���
	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	//����һ���豸
	status = IoCreateDevice(pDriverObject, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))	return status;

	//�ж�WDM�汾�Ƿ����
	if (IoIsWdmVersionAvailable(1, 0x10))
		RtlInitUnicodeString(&ustrLinkName, LINK_GLOBAL_NAME);
	else
		RtlInitUnicodeString(&ustrLinkName, LINK_NAME);
	//������������
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		//���ʧ����ɾ���������豸
		IoDeleteDevice(pDevObj);
		return status;
	}
	DbgPrint("End DriverEntry.\n");

	//��������ʼ�ı�ȫ�ֱ�����ַ
	MoveGlobleValue();

	
	
	//��ʼ�޸�Dbg���λ��
	//2�޸�KdDebuggerEnabled ��־ΪFalse
	if (*KdDebuggerEnabled)
	{
		*KdDebuggerEnabled = 0;//�޸�Ϊ��ͨģʽ
	}
	//3��֤KdDebuggerNotPresent   Debug ΪFalse
	if (!(*KdDebuggerNotPresent))
	{
		*KdDebuggerNotPresent = 1; //�޸�Ϊ��ͨģʽ
	}
	
	
		

	

	return STATUS_SUCCESS;



}



















