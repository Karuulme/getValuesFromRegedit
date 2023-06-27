#include "ntddk.h"
#include "wdm.h"
#include "ntstrsafe.h"
#define TAG_REGLIST 'tag2'
#define TAG_REGLIST_KEYS 'key2'
VOID Unload(PDRIVER_OBJECT driverObject) {
	DbgPrint("UNLOAD DRIVER");
}//GERÝ DÖNÜÞ DEÐERÝ STATUS_UNSUCCESSFULL DEÐÝLSE GÖNEN DEÐER KAYIT DEÐERÝDÝR --- if return value is not STATUS_UNSUCCESSFULL value is regedit value
NTSTATUS GetValueInRegedit(PWCHAR path, PWCHAR key) {

	//WCHAR RegistryPath[] = L"\\REGISTRY\\MACHINE\\SOFTWARE\\keys\\anahtar1";
	RTL_QUERY_REGISTRY_TABLE parameters[2];
	RtlZeroMemory(parameters, sizeof(parameters));
	NTSTATUS status;
	ULONG param = { 0 };
	parameters[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
	parameters[0].Name = key;
	parameters[0].EntryContext = &param;
	parameters[0].DefaultType = REG_DWORD;
	parameters[0].DefaultData = sizeof(param);
	status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, path, parameters, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		return STATUS_UNSUCCESSFUL;
	}
	return param;
}
NTSTATUS ReadRegedit(PUNICODE_STRING registryPath) {

	NTSTATUS status;
	HANDLE KeyHandle;
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING path;
	RtlInitUnicodeString(&path,registryPath);
	InitializeObjectAttributes(&oa, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&KeyHandle, KEY_QUERY_VALUE, &oa);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Open Key ERROR %i", status);
		ZwClose(KeyHandle);
		return status;
	}
	KEY_FULL_INFORMATION  keyic;
	ULONG size;
	ULONG resultLength;
	PKEY_BASIC_INFORMATION values = { 0 };
	PKEY_VALUE_PARTIAL_INFORMATION  keys = { 0 };
	ULONG keysResultLength;
	//DbgPrint("ADRES %wZ",path);
	WCHAR ek = L"\\";
	status = ZwQueryKey(KeyHandle, KeyFullInformation, &keyic, &size, &resultLength);
	for (ULONG i = 0; i < keyic.SubKeys; i++) {
		status = ZwEnumerateKey(KeyHandle,i,KeyBasicInformation,NULL,0,&resultLength);
		if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {
			values = (PKEY_BASIC_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, resultLength, TAG_REGLIST);
			if (values==NULL) {
				continue;
			}
		}
		status = ZwEnumerateKey(KeyHandle, i, KeyBasicInformation,values, resultLength, &resultLength);
		if (NT_SUCCESS(status)) {
			WCHAR changePath[256];
			wcscpy(changePath, path.Buffer);
			wcscat(changePath, L"\\");
			wcscat(changePath, values->Name);
			status=GetValueInRegedit(changePath,L"key");
			if (status == STATUS_UNSUCCESSFUL) {
				DbgPrint("VALUES :: HATAA ");
			}
			else {
				DbgPrint("VALUES :: %lu ", status);
			}
			
		}
		ExFreePoolWithTag(values,TAG_REGLIST);
	}
	ZwClose(KeyHandle);
	return STATUS_SUCCESS;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject,PUNICODE_STRING registryPath) {
	driverObject->DriverUnload = Unload;
	NTSTATUS status;
	status = STATUS_SUCCESS;
	//HKEY_LOCAL_MACHINE  \\Registry\\Machine
	//HKEY_USERS		  \\Registry\\User
	status=ReadRegedit(L"\\REGISTRY\\MACHINE\\SOFTWARE\\keys"); 
	DbgPrint("STATUS:: %lu",status);
	return status;
}

