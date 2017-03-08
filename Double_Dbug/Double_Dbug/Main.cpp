
#include "codemsg.h"


extern "C" PVOID  KdEnteredDebugger;
PVOID      GetKdEnteredDebuggerAddr()
{
	return KdEnteredDebugger;
}


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






// �������
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	//����ͨѶ������дж������
	pDriverObject->DriverUnload = DriverUnload;
	
	//1��ȡKdEnteredDebugger
	EnterAddr = (DWORD32 *)GetKdEnteredDebuggerAddr();
	//����API��ӡ
	DbgPrint("Value :%x\n", (int)(*EnterAddr));
	//ֱ���޸�KdEnteredDebugger
	if (*EnterAddr)
	{
		*EnterAddr = 0;
	}
	 
	
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



















