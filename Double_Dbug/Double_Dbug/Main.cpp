
#include "codemsg.h"


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
	
	DbgPrint("ж������ִ�гɹ�!");

}

extern "C" ULONG64  KdEnteredDebugger;
ULONG64        GetKdEnteredDebuggerAddr()
{
	return KdEnteredDebugger;
}



// �������
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	//����ͨѶ������дж������
	pDriverObject->DriverUnload = DriverUnload;
	ULONG64 EnterAddr = NULL;
	//���KdEnteredDebugger �ĵ�ַ
	EnterAddr = GetKdEnteredDebuggerAddr();
	//����API��ӡ
	DbgPrint("EnterAddr :%p", EnterAddr);

	
	//��ʼ�޸�Dbg���λ��
	//�޸�KdDebuggerEnabled ��־ΪFalse
	if (*KdDebuggerEnabled)
	{
		*KdDebuggerEnabled = 0;//�޸�Ϊ��ͨģʽ
	}
	//��֤KdDebuggerNotPresent   Debug ΪFalse
	if (!(*KdDebuggerNotPresent))
	{
		*KdDebuggerNotPresent = 1; //�޸�Ϊ��ͨģʽ
	}
	



	

	return STATUS_SUCCESS;



}



















