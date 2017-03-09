#include "ntddk.h"


//设备名字
#define	DEVICE_NAME			L"\\Device\\MyDoubleDrive"
//符号名字
#define LINK_NAME			L"\\DosDevices\\MyDoubleDrive"
#define LINK_GLOBAL_NAME	L"\\DosDevices\\Global\\MyDoubleDrive"

#ifndef _DEFINE_H_
#define _DEFINE_H_

// _number:    0 -> 2047 : reserved for Microsoft 微软保留
//             2047 -> 4095 : reserved for OEMs 用户自定义     
#define CODEMSG(_number) CTL_CODE(FILE_DEVICE_UNKNOWN, _number , METHOD_BUFFERED,\
	FILE_READ_DATA | FILE_WRITE_DATA)


PDEVICE_OBJECT DriverDeviceObject; // 定义一个设备对象，用于设备创建


NTSTATUS  MoveGlobleValue();


//原全局变量声明
extern "C" int  OldKdEnteredDebugger;

//自己全局变量声明
extern "C" int  MyKdEnteredDebugger = TRUE;

//定义控制码
#define INIT_FILE_NAME 2047

#endif
