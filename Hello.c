/***************************************************************************************
* AUTHOR : C005
* DATE   : 2018-7-2
* MODULE : Hello.C
* 
* Command: 
*	Source of IOCTRL Sample Driver
*
* Description:
*		Demonstrates communications between USER and KERNEL.
*
****************************************************************************************
* Copyright (C) 2010 C005.
****************************************************************************************/
#ifndef CXX_HELLO_H
#include "Hello.h"
#endif

#if MyDbg
BOOLEAN g_IsChaeck = TRUE;
BOOLEAN g_IsRemove = TRUE;
#else
BOOLEAN g_IsChaeck = FALSE;
BOOLEAN g_IsRemove = FALSE;
#define dprintf
#endif
pMiProcessLoaderEntry g_MiProcessLoaderEntry = NULL;
UCHAR g_szMiProcessLoaderEntry[41] = { 0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x6c, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57,
0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xec, 0x30, 0x48, 0x8b, 0xf9, 0x44,
0x8b, 0xf2, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d };
//#######################################################################################
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//@@@@@@@@				D R I V E R   E N T R Y   P O I N T						 @@@@@@@@
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//#######################################################################################

ULONG64 GetProcessModuleBase(IN ULONG ProcessId, IN UNICODE_STRING ModuleName)
{
	ULONG64 ModulesBase = 0;
	NTSTATUS nStatus;
	KAPC_STATE KAPC = { 0 };
	PEPROCESS  pEProcess = NULL; //EPROCESS结构指针;

	PPEB64 pPEB64 = NULL; //PEB结构指针;
	PLDR_DATA_TABLE_ENTRY64 pLdrDataEntry64 = NULL; //LDR链表入口;
	PLIST_ENTRY64 pListEntryStart64 = NULL, pListEntryEnd64 = NULL;; //链表头节点、尾节点;

	PPEB32 pPEB32 = NULL; //PEB结构指针;
	PLDR_DATA_TABLE_ENTRY32 pLdrDataEntry32 = NULL; //LDR链表入口;
	PLIST_ENTRY32 pListEntryStart32 = NULL, pListEntryEnd32 = NULL; //链表头节点、尾节点;

	//获取进程的EPROCESS结构指针;
	nStatus = PsLookupProcessByProcessId((HANDLE)ProcessId, &pEProcess);
	if (!NT_SUCCESS(nStatus) && !MmIsAddressValid(pEProcess))
	{
		return 0;
	}
	KeStackAttachProcess(pEProcess, &KAPC);

	pPEB64 = PsGetProcessPeb(pEProcess);
	pListEntryStart64 = pListEntryEnd64 = (PLIST_ENTRY64)(((PEB_LDR_DATA64*)pPEB64->Ldr)->InMemoryOrderModuleList.Flink);
	do {
		pLdrDataEntry64 = (PLDR_DATA_TABLE_ENTRY64)CONTAINING_RECORD(pListEntryStart64, LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks);
		//输出DLL基质 长度 名字;
		//DbgPrint("[Orange64] Base:%p Size:%ld Name:%wZ\n", (PVOID)pLdrDataEntry64->DllBase, (ULONG)pLdrDataEntry64->SizeOfImage, &pLdrDataEntry64->BaseDllName);

		UNICODE_STRING QueryModuleName = { 0 };
		RtlInitUnicodeString(&QueryModuleName, (PWCHAR)pLdrDataEntry64->BaseDllName.Buffer);
		if (RtlEqualUnicodeString(&ModuleName, &QueryModuleName, TRUE))
		{
			ModulesBase = (ULONG64)pLdrDataEntry64->DllBase;
			goto exit;
		}
		pListEntryStart64 = (PLIST_ENTRY64)pListEntryStart64->Flink;

	} while (pListEntryStart64 != pListEntryEnd64);

#ifdef _AMD64_	//或wow64进程;	PsIs64BitProcess

	//获取PEB指针
	pPEB32 = PsGetProcessWow64Process(pEProcess);
	pListEntryStart32 = pListEntryEnd32 = (PLIST_ENTRY32)(((PEB_LDR_DATA32*)pPEB32->Ldr)->InMemoryOrderModuleList.Flink);
	do {
		pLdrDataEntry32 = (PLDR_DATA_TABLE_ENTRY32)CONTAINING_RECORD(pListEntryStart32, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);
		//输出DLL基质 长度 名字;
		//DbgPrint("[Orange64] Base:%p Size:%ld Name:%wZ\n", (PVOID)pLdrDataEntry32->DllBase, (ULONG)pLdrDataEntry32->SizeOfImage, &pLdrDataEntry32->BaseDllName);
		UNICODE_STRING QueryModuleName = { 0 };
		RtlInitUnicodeString(&QueryModuleName, (PWCHAR)pLdrDataEntry32->BaseDllName.Buffer);
		if (RtlEqualUnicodeString(&ModuleName, &QueryModuleName, TRUE))
		{
			ModulesBase = (ULONG64)pLdrDataEntry32->DllBase;
			goto exit;
		}
		pListEntryStart32 = (PLIST_ENTRY32)pListEntryStart32->Flink;

	} while (pListEntryStart32 != pListEntryEnd32);


#endif
exit:
	KeUnstackDetachProcess(&KAPC);
	ObDereferenceObject(pEProcess);
	return ModulesBase;
}

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString)
{
	NTSTATUS		status = STATUS_SUCCESS;
	UNICODE_STRING  ustrLinkName;
	UNICODE_STRING  ustrDevName;  
	PDEVICE_OBJECT  pDevObj;
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
	pDriverObj->DriverUnload = DriverUnload;
	RtlInitUnicodeString(&ustrDevName, NT_DEVICE_NAME);

	status = IoCreateDevice(pDriverObj, 
				0,
				&ustrDevName, 
				FILE_DEVICE_UNKNOWN,
				0,
				FALSE,
				&pDevObj);


	if(!NT_SUCCESS(status))
	{
		dprintf("Hello:Error, IoCreateDevice = 0x%x\r\n", status);
		return status;
	}
	RtlInitUnicodeString(&ustrLinkName, SYMBOLIC_LINK_NAME);
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);  
	if(!NT_SUCCESS(status))
	{
		dprintf("Hello:Error, IoCreateSymbolicLink = 0x%x\r\n", status);
		IoDeleteDevice(pDevObj); 
		return status;
	}	

	dprintf("Hello:DriverEntry Success\r\n");
	return STATUS_SUCCESS;
}

VOID
DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{	
	UNICODE_STRING strLink;
	RtlInitUnicodeString(&strLink, SYMBOLIC_LINK_NAME);
	IoDeleteSymbolicLink(&strLink);
	IoDeleteDevice(pDriverObj->DeviceObject);
	dprintf("Hello:Unloaded Success\r\n");
	return;
}

NTSTATUS
DispatchCreate(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
  IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS
DispatchClose(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS
DispatchCommon(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0L;
	IoCompleteRequest( pIrp, 0 );
	return STATUS_SUCCESS;
}

NTSTATUS 
DispatchDeviceControl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
  //NTSTATUS status               = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
  ULONG uIoControlCode          = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
  PVOID pIoBuffer               = pIrp->AssociatedIrp.SystemBuffer;
  ULONG uInSize                 = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
  pIrp->IoStatus.Information    = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
  PEPROCESS pEprocess           = NULL;
  KAPC_STATE apc_state          = { 0 };
  ULONG64 uCr0                  = NULL;
  LARGE_INTEGER systemTime      = { 0 };
  LARGE_INTEGER localTime       = { 0 };
  TIME_FIELDS timeField         = { 0 };
  CSHORT Minute                 = 0;
  CSHORT Second                 = 0;
    switch (uIoControlCode)
    {
      case IOCTL_HELLO_Init_Check:
	  {
		  KeQuerySystemTime(&systemTime);
		  ExSystemTimeToLocalTime(&systemTime, &localTime);
		  RtlTimeToTimeFields(&localTime, &timeField);
		  if (timeField.Year == 2019 && timeField.Month == 7 && timeField.Day <= 16)
		  {
			  __try
			  {
				  Minute = ((PCHECKM)pIoBuffer)->uMinute ^ 0x98;
				  Second = ((PCHECKM)pIoBuffer)->uSecond ^ 0x65;
				  if (Minute == timeField.Minute && Second == timeField.Second)
				  {
					  g_IsChaeck = TRUE;
					  ((PCHECKM)pIoBuffer)->bRet = g_IsChaeck;
					  if (!g_IsRemove)
					  {
						  //移除驱动模块
						  g_IsRemove = RemoveSystemModule(pDevObj->DriverObject);
					  }
				  }
			  }
			  __except (EXCEPTION_EXECUTE_HANDLER)
			  {
				  dprintf("Hello:IOCTL_HELLO_Init_Check __except\r\n");
			  }
		  }
		  break;
	  }
      case IOCTL_HELLO_Read:
	  {
		  if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)((PREAD_WRITE_INFO)pIoBuffer)->uPid, &pEprocess)))
		  {
			  KeStackAttachProcess((PRKPROCESS)pEprocess, &apc_state);
			  __try
			  {
				  if (MmIsAddressValid((PVOID)((PREAD_WRITE_INFO)pIoBuffer)->Dst))
				  {
					  RtlCopyMemory(pIoBuffer, (PVOID)((PREAD_WRITE_INFO)pIoBuffer)->Dst, ((PREAD_WRITE_INFO)pIoBuffer)->uSize);
				  }
				  else
				  {
					  RtlZeroMemory(pIoBuffer, uInSize);
				  }
				  KeUnstackDetachProcess(&apc_state);
			  }
			  __except (EXCEPTION_EXECUTE_HANDLER)
			  {
				  KeUnstackDetachProcess(&apc_state);
				  dprintf("Hello:IOCTL_HELLO_Read __except\r\n");
			  }
		  }
		  else
		  {
			  RtlZeroMemory(pIoBuffer, uInSize);
		  }
		  break;
	  }
      case IOCTL_HELLO_Write:
	  {
		  if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)((PREAD_WRITE_INFO)pIoBuffer)->uPid, &pEprocess)))
		  {
			  KeStackAttachProcess((PRKPROCESS)pEprocess, &apc_state);
			  if (MmIsAddressValid((PVOID)((PREAD_WRITE_INFO)pIoBuffer)->Dst))
			  {
				  __try
				  {
					  _disable();
					  uCr0 = __readcr0();
					  __writecr0(uCr0 ^ 0x10000);
					  RtlCopyMemory((PVOID)((PREAD_WRITE_INFO)pIoBuffer)->Dst, (PVOID)((ULONG64)pIoBuffer + sizeof(READ_WRITE_INFO)), ((PREAD_WRITE_INFO)pIoBuffer)->uSize);
					  __writecr0(uCr0);
					  _enable();
				  }
				  __except (EXCEPTION_EXECUTE_HANDLER)
				  {
					  KeUnstackDetachProcess(&apc_state);
					  dprintf("Hello:IOCTL_HELLO_Write __except\r\n");
				  }
			  }
			  KeUnstackDetachProcess(&apc_state);
		  }
		  break;
	  }
      case IOCTL_HELLO_GetModule:
	  {
		  PREAD_WRITE_INFO GetModue = (PREAD_WRITE_INFO)pIoBuffer;
		  ANSI_STRING AnsiBuffer = { 0 };
		  UNICODE_STRING ModuleName = { 0 };
		  AnsiBuffer.Buffer = (PVOID)GetModue->Dst;
		  AnsiBuffer.Length = AnsiBuffer.MaximumLength = (USHORT)strlen((PVOID)GetModue->Dst);
		  RtlAnsiStringToUnicodeString(&ModuleName, &AnsiBuffer, TRUE);//转换
		  //DbgPrint("[Orange64] ModuleName:%wZ\n", &ModuleName);
		  *(PVOID *)pIoBuffer = GetProcessModuleBase(GetModue->uPid, ModuleName);
		 RtlFreeUnicodeString(&ModuleName);// 释放内存
		  break;
	  }
	  case IOCTL_HELLO_AllocMen:
	  {
		  if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)((PREAD_WRITE_INFO)pIoBuffer)->uPid, &pEprocess)))
		  {
			  PVOID BaseAddress = NULL;
			  __try
			  {
				  KeStackAttachProcess((PRKPROCESS)pEprocess, &apc_state);
				  ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &((PREAD_WRITE_INFO)pIoBuffer)->uSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				  RtlZeroMemory(BaseAddress, ((PREAD_WRITE_INFO)pIoBuffer)->uSize);//地址清理
				 //RtlCopyMemory(pIoBuffer, BaseAddress, sizeof(BaseAddress));
				 *(PVOID *)pIoBuffer = BaseAddress;
				 DbgPrint("[Orange64] AllocateAddr:0x%X\n", pIoBuffer);
				  KeUnstackDetachProcess(&apc_state);
			  }
			  __except (EXCEPTION_EXECUTE_HANDLER)
			  {
				  KeUnstackDetachProcess(&apc_state);
				  dprintf("Hello:IOCTL_HELLO_AllocMen __except\r\n");
			  }
		  }
	  }
    }

  pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

BOOLEAN RemoveSystemModule(PDRIVER_OBJECT pDriverObj)
{
  OSVERSIONINFOW os = { 0 };
  RtlGetVersion(&os);
  if (os.dwMajorVersion == 0x6 && os.dwMinorVersion == 0x1 && os.dwBuildNumber == 7601)
  {
    //确定是win7 64位版本 可以抹除驱动信息
    g_MiProcessLoaderEntry = GetMiProcessLoaderEntryAddr();
    if (g_MiProcessLoaderEntry)
    {
      g_MiProcessLoaderEntry((PKLDR_DATA_TABLE_ENTRY)pDriverObj->DriverSection, FALSE);

      PKLDR_DATA_TABLE_ENTRY m_Self = (PKLDR_DATA_TABLE_ENTRY)pDriverObj->DriverSection;

      PIMAGE_NT_HEADERS64 pHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)m_Self->DllBase + ((PIMAGE_DOS_HEADER)m_Self->DllBase)->e_lfanew);

      for (ULONG t = 0; t < pHeaders->OptionalHeader.NumberOfRvaAndSizes; t++)
      {
        RtlZeroMemory(&pHeaders->OptionalHeader.DataDirectory[t], sizeof(IMAGE_DATA_DIRECTORY));
      }
      PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(pHeaders->FileHeader.SizeOfOptionalHeader + (PUCHAR)&pHeaders->OptionalHeader);
      for (ULONG i = 0; i < pHeaders->FileHeader.NumberOfSections; i++)
      {
        RtlZeroMemory(pSection, sizeof(IMAGE_SECTION_HEADER));
        pSection += 1;
      }
    }
    //破坏驱动对象特征
    pDriverObj->DriverSection = NULL;
    pDriverObj->DeviceObject = NULL;
    pDriverObj->DriverStart = NULL;
    pDriverObj->DriverSize = NULL;
    pDriverObj->DriverInit = NULL;
  }
  return TRUE;
}


pMiProcessLoaderEntry GetMiProcessLoaderEntryAddr()
{
  pMiProcessLoaderEntry MiProcessLoaderEntryAddr = NULL;
  MODULE_INFO ModuleInfo = { 0 };
  UCHAR *pAddr = NULL;
  UCHAR *pEndAddr = NULL;
  int i = 0;
  //<<begin:ntoskrnl.exe|szName
  char szName[13];//ntoskrnl.exe
  *(unsigned short*)&szName[1] = (unsigned short)0x6f74;
  *(unsigned short*)&szName[7] = (unsigned short)0x2e6c;
  szName[0] = (unsigned char)0x6e;
  szName[11] = (unsigned char)0x65;
  szName[3] = (unsigned char)0x73;
  *(unsigned short*)&szName[9] = (unsigned short)0x7865;
  szName[4] = (unsigned char)0x6b;
  szName[12] = (unsigned char)0x00;
  *(unsigned short*)&szName[5] = (unsigned short)0x6e72;
  //end>>
  __try
  {
    do
    {
      if (!GetTargetModuleInfo(&ModuleInfo, szName))
      {
        break;
      }
      pEndAddr = (UCHAR*)(ModuleInfo.uBaseAddr + ModuleInfo.uBaseSize);
      for (pAddr = (UCHAR*)ModuleInfo.uBaseAddr; pAddr < pEndAddr; pAddr++)
      {
        if (MmIsAddressValid((PVOID)(pAddr)))
        {
          if (*pAddr == g_szMiProcessLoaderEntry[0])
          {
            for (i = 1; i < sizeof(g_szMiProcessLoaderEntry); i++)
            {
              if (*(pAddr + i) == g_szMiProcessLoaderEntry[i])
              {
                continue;
              }
              else
              {
                break;
              }
            }
            if (i == sizeof(g_szMiProcessLoaderEntry))
            {
              MiProcessLoaderEntryAddr = (pMiProcessLoaderEntry)pAddr;
              //dprintf("Hello:MiProcessLoaderEntry Addr =%p\r\n", MiProcessLoaderEntryAddr);
              break;
            }
          }
        }
      }
    } while (FALSE);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    dprintf("Hello:pMiProcessLoaderEntry __except\r\n");
  }
  return MiProcessLoaderEntryAddr;
}


BOOLEAN GetTargetModuleInfo(PMODULE_INFO pModuleInfo, char *szModuleName)
{
  BOOLEAN bRet = FALSE;
  PRTL_PROCESS_MODULES buf = NULL;
  ULONG ulength = 0;

  __try
  {
    do
    {
      ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &ulength);
      if (!ulength)
      {
        break;
      }

      buf = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, ulength);
      if (!buf)
      {
        break;
      }
      if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, buf, ulength, &ulength)))
      {
        ExFreePool(buf);
        break;
      }

      for (ULONG i = 0; i < buf->NumberOfModules; i++)
      {
        if (strstr((char*)buf->Modules[i].FullPathName, szModuleName))
        {
          pModuleInfo->uBaseAddr = (ULONG64)buf->Modules[i].ImageBase;
          pModuleInfo->uBaseSize = buf->Modules[i].ImageSize;
          bRet = TRUE;
          break;
        }
      }
      ExFreePool(buf);
    } while (FALSE);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    dprintf("Hello:GetTargetModuleInfo __except\r\n");
  }
  return bRet;
}