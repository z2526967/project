/**
* @brief 使用PspCidTable保护目标进程，使其所拥有的句柄表不被降权
*/


#include<wdm.h>
#include"protectProcess.h"


//使用全局句柄表保护进程,1.PspCidTable保护进程
NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING path)
{
	(path);
	driverObject->DriverUnload = DriverUnload;
	protectAndPromoteProcess(driverObject);
	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT driverObject)
{
	(driverObject);
	obUnRegister();	//注销ob句柄
}


NTSTATUS protectAndPromoteProcess(PDRIVER_OBJECT driverObject)	//这个要放在附加例程函数里
{
	//ob回调添加新的钩子，当目标进程为QQSG.exe时，使进程句柄拥有的全部权限
	//保护nb.exe进程不被其他驱动枚举句柄
	NTSTATUS status;
	status = obAddProcessAccess(driverObject);
	status = protectProcess();
	return status;
}

NTSTATUS obAddProcessAccess(PDRIVER_OBJECT driverObject)
{
	g_obHandle = NULL;
	*(PULONG)((ULONG64)driverObject->DriverSection + 0x68) |= 0x20;	//未签名验证,ob注册使用未签名处理

	OB_CALLBACK_REGISTRATION obCallbackReg = { 0 };
	OB_OPERATION_REGISTRATION obOperationReg = { 0 };

	obOperationReg.ObjectType = PsProcessType;
	obOperationReg.Operations = OB_OPERATION_HANDLE_CREATE;
	obOperationReg.PreOperation = addHanleAccess;

	obCallbackReg.Version = OB_FLT_REGISTRATION_VERSION;
	obCallbackReg.OperationRegistrationCount = 1;
	RtlInitUnicodeString(&obCallbackReg.Altitude, L"31000");
	obCallbackReg.OperationRegistration = &obOperationReg;

	NTSTATUS status = ObRegisterCallbacks(&obCallbackReg, &g_obHandle); //Bug 0xc0000022 ->未签名
	return status;
}

OB_PREOP_CALLBACK_STATUS addHanleAccess(PVOID registrationContext, POB_PRE_OPERATION_INFORMATION pObPreOperationInfo)
{
	(registrationContext);
	if (pObPreOperationInfo->Operation == OB_OPERATION_HANDLE_CREATE && *PsProcessType == pObPreOperationInfo->ObjectType)
	{
		PEPROCESS pEProcess = (PEPROCESS)pObPreOperationInfo->Object;
		// 判断操作类型是创建句柄
		if (isProtectProcess(pEProcess)) // 是否是要保护的进程
		{
			pObPreOperationInfo->Parameters->CreateHandleInformation.DesiredAccess = 0x1fffff;
			pObPreOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0x1fffff;
		}
	}
	return OB_PREOP_SUCCESS;
}


BOOLEAN isProtectProcess(PEPROCESS pEProcess)
{
	BOOLEAN bRet = FALSE;
	PUCHAR pProcName = PsGetProcessImageFileName(pEProcess); // 获取进程名

	if (pProcName)
	{
		if (strcmp((const char*)pProcName, desProcessName) == 0)
		{
			bRet = TRUE;
		}
	}
	return bRet;
}

void obUnRegister() {
	if (g_obHandle) {
		ObUnRegisterCallbacks(g_obHandle);
	}
}

NTSTATUS protectProcess()
{
	NTSTATUS status;
	PEPROCESS PEprocess;
	status = PsLookupProcessByProcessName(&PEprocess);
	HANDLE handle = PsGetProcessId(PEprocess);
	if (!NT_SUCCESS(status)) return status;		//2022/11/3 6:21测试通过

	UNICODE_STRING unicode_string = { 0 };
	RtlInitUnicodeString(&unicode_string, L"PsLookupProcessByProcessId");
	PVOID PsLookupProcessByProcessIdAddr = MmGetSystemRoutineAddress(&unicode_string);
	PVOID offset = (PVOID)((ULONG64)PsLookupProcessByProcessIdAddr + 0x25);
	ULONG64 PspCidTableEntry = (ULONG64)PsLookupProcessByProcessIdAddr + 0x25 + 0x4 + *(PULONG32)offset;
	offset = (PVOID)(PspCidTableEntry + 0x1d);
	ULONG64 PspCidTable = (ULONG64)PspCidTableEntry + 0x1d + 0x4 + *(PULONG32)offset;
	ULONG64 PHandleTableEntry = ExpLookupHandleTableEntry((unsigned int*)PspCidTable, (__int64)handle);

	*(PULONG64)PHandleTableEntry = 0;
	*(PULONG64)((ULONG64)PEprocess + 0x2e0) = 0;

	return status;
}


//功能:进程名,进程结构
//测试通过
NTSTATUS PsLookupProcessByProcessName(OUT PEPROCESS* outPEprocess)
{
	PLIST_ENTRY list = NULL;
	PLIST_ENTRY entry = NULL;
	CHAR* processName;
	PEPROCESS PEprocess = PsGetCurrentProcess();
	entry = (PLIST_ENTRY)((ULONG64)PEprocess + 0x448);
	list = entry;

	do
	{
		processName = (char*)PsGetProcessImageFileName(PEprocess);
		//DbgPrint("debug:%s", processName);
		if (strcmp(processName, ceName) == 0) {
			*outPEprocess = PEprocess;
			return STATUS_SUCCESS;
		}
		list = list->Flink;
		PEprocess = (PEPROCESS)((ULONG64)list - 0x448);
	} while (entry != list);

	return STATUS_NOT_FOUND;
}


//PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(const ULONG64* pHandleTable, const LONGLONG Handle)
__int64 __fastcall ExpLookupHandleTableEntry(unsigned int* a1, __int64 a2)
{
	unsigned __int64 v2; // rdx
	__int64 v3; // r8

	v2 = a2 & 0xFFFFFFFFFFFFFFFC;
	if (v2 >= *a1)
		return 0;
	v3 = *((ULONG64*)a1 + 1);
	if ((v3 & 3) == 1)
		return *(ULONG64*)(v3 + 8 * (v2 >> 10) - 1) + 4 * (v2 & 0x3FF);
	if ((v3 & 3) != 0)
		return *(ULONG64*)(*(ULONG64*)(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF)) + 4 * (v2 & 0x3FF);
	return v3 + 4 * v2;
}