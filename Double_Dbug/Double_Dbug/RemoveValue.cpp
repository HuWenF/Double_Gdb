#include "codemsg.h"



//获得KdEnteredDebugger 地址
int     GetKdEnteredDebuggerAddr()
{
	return OldKdEnteredDebugger;
}


NTSTATUS MoveGlobleValue()
{

	//1获取KdEnteredDebugger
	GetKdEnteredDebuggerAddr();







}










