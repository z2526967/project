/**
* @brief ʹ��PspCidTable����Ŀ����̣�ʹ����ӵ�еľ��������Ȩ
*/


#include<wdm.h>
#include"protectProcess.h"


//ʹ��ȫ�־����������,1.PspCidTable��������
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
	obUnRegister();	//ע��ob���
}


NTSTATUS protectAndPromoteProcess(PDRIVER_OBJECT driverObject)	//���Ҫ���ڸ������̺�����
{
	//ob�ص�����µĹ��ӣ���Ŀ�����ΪQQSG.exeʱ��ʹ���̾��ӵ�е�ȫ��Ȩ��
	//����nb.exe���̲�����������ö�پ��
	NTSTATUS status;
	status = obAddProcessAccess(driverObject);
	status = protectProcess();
	return status;
}

NTSTATUS obAddProcessAccess(PDRIVER_OBJECT driverObject)
{
	g_obHandle = NULL;
	*(PULONG)((ULONG64)driverObject->DriverSection + 0x68) |= 0x20;	//δǩ����֤,obע��ʹ��δǩ������

	OB_CALLBACK_REGISTRATION obCallbackReg = { 0 };
	OB_OPERATION_REGISTRATION obOperationReg = { 0 };

	obOperationReg.ObjectType = PsProcessType;
	obOperationReg.Operations = OB_OPERATION_HANDLE_CREATE;
	obOperationReg.PreOperation = addHanleAccess;

	obCallbackReg.Version = OB_FLT_REGISTRATION_VERSION;
	obCallbackReg.OperationRegistrationCount = 1;
	RtlInitUnicodeString(&obCallbackReg.Altitude, L"31000");
	obCallbackReg.OperationRegistration = &obOperationReg;

	NTSTATUS status = ObRegisterCallbacks(&obCallbackReg, &g_obHandle); //Bug 0xc0000022 ->δǩ��
	return status;
}

OB_PREOP_CALLBACK_STATUS addHanleAccess(PVOID registrationContext, POB_PRE_OPERATION_INFORMATION pObPreOperationInfo)
{
	(registrationContext);
	if (pObPreOperationInfo->Operation == OB_OPERATION_HANDLE_CREATE && *PsProcessType == pObPreOperationInfo->ObjectType)
	{
		PEPROCESS pEProcess = (PEPROCESS)pObPreOperationInfo->Object;
		// �жϲ��������Ǵ������
		if (isProtectProcess(pEProcess)) // �Ƿ���Ҫ�����Ľ���
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
	PUCHAR pProcName = PsGetProcessImageFileName(pEProcess); // ��ȡ������

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
	if (!NT_SUCCESS(status)) return status;		//2022/11/3 6:21����ͨ��

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


//����:������,���̽ṹ
//����ͨ��
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