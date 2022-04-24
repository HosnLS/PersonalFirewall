#include "precomp.h"
#include "firewall.h"

//#include "ntstrsafe.h"
//#define DbgOutStrLen 200
//LONG DbgOutString(CONST PCHAR string);
//LONG DbgOutString(CONST PCHAR string) {
//	HANDLE SourceFileHandle = NULL;      //源文件句柄
//	NTSTATUS Status = STATUS_SUCCESS;    //返回状态
//	OBJECT_ATTRIBUTES ObjectAttributes;  //OBJECT_ATTRIBUTES结构
//	UNICODE_STRING SourceFilePath = RTL_CONSTANT_STRING(L"\\DosDevices\\C:\\log.txt"); //源文件
//	IO_STATUS_BLOCK IoStatusBlock;         //返回结果状态结构体
//	LARGE_INTEGER Offset = { 0 };
//	FILE_STANDARD_INFORMATION fileInfo = { 0 };
//	InitializeObjectAttributes(
//		&ObjectAttributes,
//		&SourceFilePath,
//		OBJ_CASE_INSENSITIVE,
//		NULL,
//		NULL);
//	Status = ZwCreateFile(
//		&SourceFileHandle,
//		GENERIC_WRITE | SYNCHRONIZE,
//		&ObjectAttributes,
//		&IoStatusBlock,
//		NULL,
//		FILE_ATTRIBUTE_NORMAL,
//		FILE_SHARE_READ,
//		FILE_OPEN_IF,
//		FILE_SYNCHRONOUS_IO_NONALERT,
//		NULL,
//		0);
//	if (!NT_SUCCESS(Status))
//	{
//		return 0;
//	}
//	Status = ZwQueryInformationFile(
//		SourceFileHandle,
//		&IoStatusBlock,
//		&fileInfo,
//		sizeof(fileInfo),
//		FileStandardInformation
//	);
//	if (!NT_SUCCESS(Status)) {
//		ZwClose(SourceFileHandle);
//		return 0;
//	}
//	Offset = fileInfo.EndOfFile;
//	LONG i = 0;
//	while (string[i] != 0) ++i;
//	Status = ZwWriteFile(
//		SourceFileHandle,
//		NULL,
//		NULL,
//		NULL,
//		&IoStatusBlock,
//		string,
//		i,
//		&Offset,
//		NULL
//	);
//	ZwClose(SourceFileHandle);
//	return NT_SUCCESS(Status) ? 1 : 0;
//}
//#define DbgOut(...)													\
//{																		\
//	CHAR destStr[DbgOutStrLen] = {0};													\
//	RtlStringCbPrintfA(destStr, DbgOutStrLen * sizeof(CHAR), __VA_ARGS__);		\
//	DbgOutString(destStr);													\
//}

// return 1 if comfort
LONG judgeFrameSingle(CONST FirewallEntry* pEntry,CONST PUCHAR pDataAddr, CONST ULONG uDataLenth, CONST LONG lDataMode) {
	uDataLenth;
	PUCHAR pLink, pNet, pTrans;
	pLink = pDataAddr;
	// judge direction
	if (!(pEntry->Rule.direction&In) && (lDataMode == U_CNBL_RECEIVE)) return 0;
	if (!(pEntry->Rule.direction&Out) && (lDataMode == U_CNBL_SEND)) return 0;
	// ethernet header
	// judge mac
	for (LONG i = 0; i < 6; i++)
	{
		if ((pEntry->Rule.srcMacs.mask[i] & ((ETHERNET_HEADER*)pLink)->SrcMac[i]) != pEntry->Rule.srcMacs.mac[i])return 0;
		if ((pEntry->Rule.dstMacs.mask[i] & ((ETHERNET_HEADER*)pLink)->DstMac[i]) != pEntry->Rule.dstMacs.mac[i])return 0;
	}
	// calculate network head pointer
	pNet = pLink + sizeof(ETHERNET_HEADER);
	// judge ether type  
	// DEBUGP(DL_WARN, "EthType %x\n", ((ETHERNET_HEADER*)pLink)->EthType);
	switch (((ETHERNET_HEADER*)pLink)->EthType) {
	case 0x0008:	// IPv4
		if (pEntry->Rule.protocol != Any 
			&& pEntry->Rule.protocol != IPv4
			&& pEntry->Rule.protocol != ICMP
			&& pEntry->Rule.protocol != IPSec
			&& pEntry->Rule.protocol != TCP
			&& pEntry->Rule.protocol != UDP
			&& pEntry->Rule.protocol != L2TP)
			return 0;
		// src IP
		if (pEntry->Rule.srcIps.version == 4)
			for (LONG i = 0; i < 4; i++)
			{
				if ((pEntry->Rule.srcIps.mask[i] & ((IPV4_HEADER*)pNet)->SrcAddr[i]) != pEntry->Rule.srcIps.ip[i])return 0;
			}
		// des IP
		if (pEntry->Rule.dstIps.version == 4)
			for (LONG i = 0; i < 4; i++)
			{
				if ((pEntry->Rule.dstIps.mask[i] & ((IPV4_HEADER*)pNet)->DstAddr[i]) != pEntry->Rule.dstIps.ip[i])return 0;
			}
		// calculate transport head pointer
		pTrans = pNet + (((IPV4_HEADER*)pNet)->VH & 16) * 4;
		switch (((IPV4_HEADER*)pNet)->Protocol) {
		case 1:		// ICMP
			if (pEntry->Rule.protocol != Any
				&& pEntry->Rule.protocol != IPv4
				&& pEntry->Rule.protocol != ICMP)
				return 0;
			break;
		case 6:		// TCP
			if (pEntry->Rule.protocol != Any
				&& pEntry->Rule.protocol != IPv4
				&& pEntry->Rule.protocol != TCP)
				return 0;
			if (((TCP_HEADER*)pTrans)->SrcPort < pEntry->Rule.srcPorts.startPort || ((TCP_HEADER*)pTrans)->SrcPort > pEntry->Rule.srcPorts.endPort) return 0;
			if (((TCP_HEADER*)pTrans)->DstPort < pEntry->Rule.dstPorts.startPort || ((TCP_HEADER*)pTrans)->DstPort > pEntry->Rule.dstPorts.endPort) return 0;
			break;
		case 17:	// UDP
			if (pEntry->Rule.protocol != Any
				&& pEntry->Rule.protocol != IPv4
				&& pEntry->Rule.protocol != UDP
				&& pEntry->Rule.protocol != L2TP)
				return 0;
			if (((UDP_HEADER*)pTrans)->SrcPort < pEntry->Rule.srcPorts.startPort || ((UDP_HEADER*)pTrans)->SrcPort > pEntry->Rule.srcPorts.endPort) return 0;
			if (((UDP_HEADER*)pTrans)->DstPort < pEntry->Rule.dstPorts.startPort || ((UDP_HEADER*)pTrans)->DstPort > pEntry->Rule.dstPorts.endPort) return 0;
			break;
		case 50:	//ESP
			if (pEntry->Rule.protocol != Any
				&& pEntry->Rule.protocol != IPv4
				&& pEntry->Rule.protocol != IPSec)
				return 0;
			break;
		case 51:	//AH
			if (pEntry->Rule.protocol != Any
				&& pEntry->Rule.protocol != IPv4
				&& pEntry->Rule.protocol != IPSec)
				return 0;
			break;
		default:
			break;
		}
		break;
	case 0x0608:	// ARP
		if (pEntry->Rule.protocol != Any
			&& pEntry->Rule.protocol != ARP)
			return 0;
		break;
	case 0xDD86:	// IPv6
		if (pEntry->Rule.protocol != Any
			&& pEntry->Rule.protocol != IPv6
			&& pEntry->Rule.protocol != ICMP
			&& pEntry->Rule.protocol != IPSec
			&& pEntry->Rule.protocol != TCP
			&& pEntry->Rule.protocol != UDP
			&& pEntry->Rule.protocol != L2TP)
			return 0;
		// src IP
		if (pEntry->Rule.srcIps.version == 6)
			for (LONG i = 0; i < 16; i++)
			{
				if ((pEntry->Rule.srcIps.mask[i] & ((IPV6_HEADER*)pNet)->SrcAddr[i]) != pEntry->Rule.srcIps.ip[i])return 0;
			}
		// des IP
		if (pEntry->Rule.dstIps.version == 6)
			for (LONG i = 0; i < 16; i++)
			{
				if ((pEntry->Rule.dstIps.mask[i] & ((IPV6_HEADER*)pNet)->DstAddr[i]) != pEntry->Rule.dstIps.ip[i])return 0;
			}
		// calculate transport head pointer
		pTrans = pNet + sizeof(IPV6_HEADER);
		switch (((IPV6_HEADER*)pNet)->Protocol) {
		case 1:		// ICMP
			if (pEntry->Rule.protocol != Any
				&& pEntry->Rule.protocol != IPv6
				&& pEntry->Rule.protocol != ICMP)
				return 0;
			break;
		case 6:		// TCP
			if (pEntry->Rule.protocol != Any
				&& pEntry->Rule.protocol != IPv6
				&& pEntry->Rule.protocol != TCP)
				return 0;
			if (((TCP_HEADER*)pTrans)->SrcPort < pEntry->Rule.srcPorts.startPort || ((TCP_HEADER*)pTrans)->SrcPort > pEntry->Rule.srcPorts.endPort) return 0;
			if (((TCP_HEADER*)pTrans)->DstPort < pEntry->Rule.dstPorts.startPort || ((TCP_HEADER*)pTrans)->DstPort > pEntry->Rule.dstPorts.endPort) return 0;
			break;
		case 17:	// UDP
			if (pEntry->Rule.protocol != Any
				&& pEntry->Rule.protocol != IPv6
				&& pEntry->Rule.protocol != UDP
				&& pEntry->Rule.protocol != L2TP)
				return 0;
			if (((UDP_HEADER*)pTrans)->SrcPort < pEntry->Rule.srcPorts.startPort || ((UDP_HEADER*)pTrans)->SrcPort > pEntry->Rule.srcPorts.endPort) return 0;
			if (((UDP_HEADER*)pTrans)->DstPort < pEntry->Rule.dstPorts.startPort || ((UDP_HEADER*)pTrans)->DstPort > pEntry->Rule.dstPorts.endPort) return 0;
			break;
		case 50:	//ESP
			if (pEntry->Rule.protocol != Any
				&& pEntry->Rule.protocol != IPv6
				&& pEntry->Rule.protocol != IPSec)
				return 0;
			break;
		case 51:	//AH
			if (pEntry->Rule.protocol != Any
				&& pEntry->Rule.protocol != IPv6
				&& pEntry->Rule.protocol != IPSec)
				return 0;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
	return 1;
}

LONG UJudgeFrame(CONST PUCHAR pDataAddr, CONST ULONG uDataLenth, CONST LONG lDataMode) {
	BOOLEAN bFalse = FALSE;
	LONG judgeResult;		// 单次规则判定结果
	for (LONG i = 0; i < RULE_MAX_LENGTH; i++)
	{
		if (!FWEntryTable[i].Present || !FWEntryTable[i].Enabled) continue;
		judgeResult = judgeFrameSingle(FWEntryTable + i, pDataAddr, uDataLenth, lDataMode);
		if (judgeResult) {
			DEBUGP(DL_WARN, "No:%d\tName:%s\tStatistic:%d\n", FWEntryTable[i].Rule.id, FWEntryTable[i].Rule.name, FWEntryTable[i].Statistic);
			FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
			FWEntryTable[i].Statistic += 1;
			FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
			return 0;
		}
	}
	return 1;
};
ULONG UProcessIO(CONST PCHAR pInBufferAddr, CONST ULONG uInBufferLength, CONST ULONG uOutBufferLength) {
	pInBufferAddr;
	uInBufferLength;
	uOutBufferLength;
	PCHAR pBuffer = pInBufferAddr;
	PCHAR pEntry = (PCHAR)FWEntryTable;
	switch(*pBuffer){
	case 0:		// fetch
		//if (uOutBufferLength < sizeof(FWEntryTable) + 1) {
		//	DEBUGP(DL_ERROR, "Fetch FWEntryTable Failed! Required Size : %d\n", sizeof(FWEntryTable));
		//	pInBufferAddr[0] = 0;		// fail
		//	return 1;
		//}
		pBuffer = pInBufferAddr + 8;
		for (LONG i = 0; i < RULE_MAX_LENGTH; i++)
		{
			*((PLONG)pBuffer) = FWEntryTable[i].Rule.id;
			pBuffer += 4;		// id
			pEntry = (PCHAR)FWEntryTable[i].Rule.name;
			while (*pEntry) *(pBuffer++) = *(pEntry++);
			*pBuffer = *pEntry;
			pBuffer += 1;		// name
			*((PUCHAR)pBuffer) = (UCHAR)((FWEntryTable[i].Rule.direction << 6) | (FWEntryTable[i].Rule.protocol));
			pBuffer += 1;	// direction protocol
			for (LONG j = 0; j < 6; j++) *(pBuffer++) = FWEntryTable[i].Rule.srcMacs.mac[j];
			for (LONG j = 0; j < 6; j++) *(pBuffer++) = FWEntryTable[i].Rule.srcMacs.mask[j]; // srcMacs
			for (LONG j = 0; j < 6; j++) *(pBuffer++) = FWEntryTable[i].Rule.dstMacs.mac[j];
			for (LONG j = 0; j < 6; j++) *(pBuffer++) = FWEntryTable[i].Rule.dstMacs.mask[j]; // dstMacs
			*(pBuffer++) = FWEntryTable[i].Rule.srcIps.version;
			if (FWEntryTable[i].Rule.srcIps.version == 4) {
				for (LONG j = 0; j < 4; j++) *(pBuffer++) = FWEntryTable[i].Rule.srcIps.ip[j];
				for (LONG j = 0; j < 4; j++) *(pBuffer++) = FWEntryTable[i].Rule.srcIps.mask[j]; // srcIps
			}
			else {
				for (LONG j = 0; j < 16; j++) *(pBuffer++) = FWEntryTable[i].Rule.srcIps.ip[j];
				for (LONG j = 0; j < 16; j++) *(pBuffer++) = FWEntryTable[i].Rule.srcIps.mask[j]; // srcIps
			}
			*(pBuffer++) = FWEntryTable[i].Rule.dstIps.version;
			if (FWEntryTable[i].Rule.dstIps.version == 4) {
				for (LONG j = 0; j < 4; j++) *(pBuffer++) = FWEntryTable[i].Rule.dstIps.ip[j];
				for (LONG j = 0; j < 4; j++) *(pBuffer++) = FWEntryTable[i].Rule.dstIps.mask[j]; // dstIps
			}
			else {
				for (LONG j = 0; j < 16; j++) *(pBuffer++) = FWEntryTable[i].Rule.dstIps.ip[j];
				for (LONG j = 0; j < 16; j++) *(pBuffer++) = FWEntryTable[i].Rule.dstIps.mask[j]; // dstIps
			}
			*((PUSHORT)pBuffer) = FWEntryTable[i].Rule.srcPorts.startPort;
			pBuffer += 2;		
			*((PUSHORT)pBuffer) = FWEntryTable[i].Rule.srcPorts.endPort;
			pBuffer += 2;		// srcPorts
			*((PUSHORT)pBuffer) = FWEntryTable[i].Rule.dstPorts.startPort;
			pBuffer += 2;
			*((PUSHORT)pBuffer) = FWEntryTable[i].Rule.dstPorts.endPort;
			pBuffer += 2;		// dstPorts
			*((PUCHAR)pBuffer) = (FWEntryTable[i].Present << 1) | (FWEntryTable[i].Enabled);
			pBuffer += 1;		// present enabled
			*((PULONGLONG)pBuffer) = FWEntryTable[i].Statistic;
			pBuffer += 8;		// Statistic
		}
		*(PULONGLONG)(pInBufferAddr) = RULE_MAX_LENGTH;			// success
		DEBUGP(DL_WARN, "Fetch Success!");
		return sizeof(FWEntryTable) + 1;
	case 1:		// set
		//if (uInBufferLength < sizeof(FWEntryTable) + 1) {
		//	DEBUGP(DL_ERROR, "Set FWEntryTable Failed! Input %d Not Match Required %d\n", uInBufferLength, sizeof(FWEntryTable) + 1);
		//	pInBufferAddr[0] = 0;		// fail
		//	return 1;
		//}
		pBuffer = pInBufferAddr + 9;
		for (LONG i = 0; i < min(*(PLONGLONG)(pInBufferAddr + 1), RULE_MAX_LENGTH); i++)
		{
			FWEntryTable[i].Rule.id = *((PLONG)pBuffer);
			pBuffer += 4;		// id
			pEntry = (PCHAR)FWEntryTable[i].Rule.name;
			while (*pBuffer) *(pEntry++) = *(pBuffer++);
			*pEntry = *pBuffer;
			pBuffer += 1;		// name
			FWEntryTable[i].Rule.direction = *((PUCHAR)pBuffer) >> 6;
			FWEntryTable[i].Rule.protocol = *((PUCHAR)pBuffer) & 0b111111;
			pBuffer += 1;	// direction protocol
			for (LONG j = 0; j < 6; j++) FWEntryTable[i].Rule.srcMacs.mac[j] = *(pBuffer++);
			for (LONG j = 0; j < 6; j++) FWEntryTable[i].Rule.srcMacs.mask[j] = *(pBuffer++); // srcMacs
			for (LONG j = 0; j < 6; j++) FWEntryTable[i].Rule.dstMacs.mac[j] = *(pBuffer++);
			for (LONG j = 0; j < 6; j++) FWEntryTable[i].Rule.dstMacs.mask[j] = *(pBuffer++); // dstMacs
			FWEntryTable[i].Rule.srcIps.version = *(pBuffer++);
			if (FWEntryTable[i].Rule.srcIps.version == 4) {
				for (LONG j = 0; j < 4; j++) FWEntryTable[i].Rule.srcIps.ip[j] = *(pBuffer++);
				for (LONG j = 0; j < 4; j++) FWEntryTable[i].Rule.srcIps.mask[j] = *(pBuffer++); // srcIps
			}
			else {
				for (LONG j = 0; j < 16; j++) FWEntryTable[i].Rule.srcIps.ip[j] = *(pBuffer++);
				for (LONG j = 0; j < 16; j++) FWEntryTable[i].Rule.srcIps.mask[j] = *(pBuffer++); // srcIps
			}
			FWEntryTable[i].Rule.dstIps.version = *(pBuffer++);
			if (FWEntryTable[i].Rule.dstIps.version == 4) {
				for (LONG j = 0; j < 4; j++) FWEntryTable[i].Rule.dstIps.ip[j] = *(pBuffer++);
				for (LONG j = 0; j < 4; j++) FWEntryTable[i].Rule.dstIps.mask[j] = *(pBuffer++); // dstIps
			}
			else {
				for (LONG j = 0; j < 16; j++) FWEntryTable[i].Rule.dstIps.ip[j] = *(pBuffer++);
				for (LONG j = 0; j < 16; j++) FWEntryTable[i].Rule.dstIps.mask[j] = *(pBuffer++); // dstIps
			}
			FWEntryTable[i].Rule.srcPorts.startPort = *((PUSHORT)pBuffer);
			pBuffer += 2;
			FWEntryTable[i].Rule.srcPorts.endPort = *((PUSHORT)pBuffer);
			pBuffer += 2;		// srcPorts
			FWEntryTable[i].Rule.dstPorts.startPort = *((PUSHORT)pBuffer);
			pBuffer += 2;
			FWEntryTable[i].Rule.dstPorts.endPort = *((PUSHORT)pBuffer);
			pBuffer += 2;		// dstPorts
			FWEntryTable[i].Present = (*((PUCHAR)pBuffer) >> 1) & 0b1;
			FWEntryTable[i].Enabled = *((PUCHAR)pBuffer) & 0b1;
			pBuffer += 1;		// present enabled
			FWEntryTable[i].Statistic = *((PULONGLONG)pBuffer);
			pBuffer += 8;		// Statistic
			DEBUGP(DL_WARN, "%d %x %x", i, FWEntryTable[i].Present, FWEntryTable[i].Enabled);
		}
		for (LONG i = (LONG)min(*(PLONGLONG)(pInBufferAddr + 1), RULE_MAX_LENGTH); i < RULE_MAX_LENGTH; i++) {
			FWEntryTable[i].Present = 0;
			FWEntryTable[i].Enabled = 0;
			FWEntryTable[i].Rule.name[0] = 0;
			DEBUGP(DL_WARN, "%d %x %x", i, FWEntryTable[i].Present, FWEntryTable[i].Enabled);
		}
		*pInBufferAddr = 1;			// success
		DEBUGP(DL_WARN, "Post Success!");
		return sizeof(FWEntryTable) + 1;
	}
	return 1;
}

// Initialize Firewall Entry
LONG UInitProfile() {
	BOOLEAN bFalse = FALSE;
	FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
	for (LONG i = 0; i < RULE_MAX_LENGTH; i++)
	{
		FWEntryTable[i].Present = 0;
		FWEntryTable[i].Enabled = 0;
		FWEntryTable[i].Statistic = 0;
		FWEntryTable[i].Rule.id = (UCHAR)i;
		FWEntryTable[i].Rule.name[0] = 'p';
		FWEntryTable[i].Rule.name[1] = '\0';
		FWEntryTable[i].Rule.srcIps.version = 4;
		FWEntryTable[i].Rule.dstIps.version = 4;
	}
	// ban ICPM To 192.168.142.2
	FWEntryTable[0].Present = 1;
	FWEntryTable[0].Enabled = 1;
	FWEntryTable[0].Rule.id = 0;
	FWEntryTable[0].Rule.name[0] = 'p';
	FWEntryTable[0].Rule.name[1] = 'i';
	FWEntryTable[0].Rule.name[2] = 'n';
	FWEntryTable[0].Rule.name[3] = 'g';
	FWEntryTable[0].Rule.name[4] = '\0';
	FWEntryTable[0].Rule.protocol = ICMP;
	FWEntryTable[0].Rule.direction = InOut;
	FWEntryTable[0].Rule.srcMacs.mac[0] = 0;
	FWEntryTable[0].Rule.srcMacs.mac[1] = 0;
	FWEntryTable[0].Rule.srcMacs.mac[2] = 0;
	FWEntryTable[0].Rule.srcMacs.mac[3] = 0;
	FWEntryTable[0].Rule.srcMacs.mac[4] = 0;
	FWEntryTable[0].Rule.srcMacs.mac[5] = 0;
	FWEntryTable[0].Rule.srcMacs.mask[0] = 0;
	FWEntryTable[0].Rule.srcMacs.mask[1] = 0;
	FWEntryTable[0].Rule.srcMacs.mask[2] = 0;
	FWEntryTable[0].Rule.srcMacs.mask[3] = 0;
	FWEntryTable[0].Rule.srcMacs.mask[4] = 0;
	FWEntryTable[0].Rule.srcMacs.mask[5] = 0;
	FWEntryTable[0].Rule.dstMacs.mac[0] = 0;
	FWEntryTable[0].Rule.dstMacs.mac[1] = 0;
	FWEntryTable[0].Rule.dstMacs.mac[2] = 0;
	FWEntryTable[0].Rule.dstMacs.mac[3] = 0;
	FWEntryTable[0].Rule.dstMacs.mac[4] = 0;
	FWEntryTable[0].Rule.dstMacs.mac[5] = 0;
	FWEntryTable[0].Rule.dstMacs.mask[0] = 0;
	FWEntryTable[0].Rule.dstMacs.mask[1] = 0;
	FWEntryTable[0].Rule.dstMacs.mask[2] = 0;
	FWEntryTable[0].Rule.dstMacs.mask[3] = 0;
	FWEntryTable[0].Rule.dstMacs.mask[4] = 0;
	FWEntryTable[0].Rule.dstMacs.mask[5] = 0;
	FWEntryTable[0].Rule.srcIps.version = 4;
	FWEntryTable[0].Rule.srcIps.ip[1] = 0;
	FWEntryTable[0].Rule.srcIps.ip[2] = 0;
	FWEntryTable[0].Rule.srcIps.ip[3] = 0;
	FWEntryTable[0].Rule.srcIps.ip[4] = 0;
	FWEntryTable[0].Rule.srcIps.mask[0] = 0;
	FWEntryTable[0].Rule.srcIps.mask[1] = 0;
	FWEntryTable[0].Rule.srcIps.mask[2] = 0;
	FWEntryTable[0].Rule.srcIps.mask[3] = 0;
	FWEntryTable[0].Rule.dstIps.version = 4;
	FWEntryTable[0].Rule.dstIps.ip[0] = 192;
	FWEntryTable[0].Rule.dstIps.ip[1] = 168;
	FWEntryTable[0].Rule.dstIps.ip[2] = 142;
	FWEntryTable[0].Rule.dstIps.ip[3] = 2;
	FWEntryTable[0].Rule.dstIps.mask[0] = 255;
	FWEntryTable[0].Rule.dstIps.mask[1] = 255;
	FWEntryTable[0].Rule.dstIps.mask[2] = 255;
	FWEntryTable[0].Rule.dstIps.mask[3] = 255;
	FWEntryTable[0].Rule.srcPorts.startPort = 0;
	FWEntryTable[0].Rule.srcPorts.endPort = (USHORT)65535;
	FWEntryTable[0].Rule.dstPorts.startPort = 0;
	FWEntryTable[0].Rule.dstPorts.endPort = (USHORT)65535;

	// Ban IPv4 To 182.61.200.*
	FWEntryTable[1].Present = 1;
	FWEntryTable[1].Enabled = 1;
	FWEntryTable[1].Rule.id = 1;
	FWEntryTable[1].Rule.name[0] = 'b';
	FWEntryTable[1].Rule.name[1] = 'a';
	FWEntryTable[1].Rule.name[2] = 'i';
	FWEntryTable[1].Rule.name[3] = 'd';
	FWEntryTable[1].Rule.name[4] = 'u';
	FWEntryTable[1].Rule.name[5] = '\0';
	FWEntryTable[1].Rule.protocol = IPv4;
	FWEntryTable[1].Rule.direction = InOut;
	FWEntryTable[1].Rule.srcMacs.mac[0] = 0;
	FWEntryTable[1].Rule.srcMacs.mac[1] = 0;
	FWEntryTable[1].Rule.srcMacs.mac[2] = 0;
	FWEntryTable[1].Rule.srcMacs.mac[3] = 0;
	FWEntryTable[1].Rule.srcMacs.mac[4] = 0;
	FWEntryTable[1].Rule.srcMacs.mac[5] = 0;
	FWEntryTable[1].Rule.srcMacs.mask[0] = 0;
	FWEntryTable[1].Rule.srcMacs.mask[1] = 0;
	FWEntryTable[1].Rule.srcMacs.mask[2] = 0;
	FWEntryTable[1].Rule.srcMacs.mask[3] = 0;
	FWEntryTable[1].Rule.srcMacs.mask[4] = 0;
	FWEntryTable[1].Rule.srcMacs.mask[5] = 0;
	FWEntryTable[1].Rule.dstMacs.mac[0] = 0;
	FWEntryTable[1].Rule.dstMacs.mac[1] = 0;
	FWEntryTable[1].Rule.dstMacs.mac[2] = 0;
	FWEntryTable[1].Rule.dstMacs.mac[3] = 0;
	FWEntryTable[1].Rule.dstMacs.mac[4] = 0;
	FWEntryTable[1].Rule.dstMacs.mac[5] = 0;
	FWEntryTable[1].Rule.dstMacs.mask[0] = 0;
	FWEntryTable[1].Rule.dstMacs.mask[1] = 0;
	FWEntryTable[1].Rule.dstMacs.mask[2] = 0;
	FWEntryTable[1].Rule.dstMacs.mask[3] = 0;
	FWEntryTable[1].Rule.dstMacs.mask[4] = 0;
	FWEntryTable[1].Rule.dstMacs.mask[5] = 0;
	FWEntryTable[1].Rule.srcIps.version = 4;
	FWEntryTable[1].Rule.srcIps.ip[1] = 0;
	FWEntryTable[1].Rule.srcIps.ip[2] = 0;
	FWEntryTable[1].Rule.srcIps.ip[3] = 0;
	FWEntryTable[1].Rule.srcIps.ip[4] = 0;
	FWEntryTable[1].Rule.srcIps.mask[0] = 0;
	FWEntryTable[1].Rule.srcIps.mask[1] = 0;
	FWEntryTable[1].Rule.srcIps.mask[2] = 0;
	FWEntryTable[1].Rule.srcIps.mask[3] = 0;
	FWEntryTable[1].Rule.dstIps.version = 4;
	FWEntryTable[1].Rule.dstIps.ip[0] = 182;
	FWEntryTable[1].Rule.dstIps.ip[1] = 61;
	FWEntryTable[1].Rule.dstIps.ip[2] = 200;
	FWEntryTable[1].Rule.dstIps.ip[3] = 0;
	FWEntryTable[1].Rule.dstIps.mask[0] = 255;
	FWEntryTable[1].Rule.dstIps.mask[1] = 255;
	FWEntryTable[1].Rule.dstIps.mask[2] = 255;
	FWEntryTable[1].Rule.dstIps.mask[3] = 0;
	FWEntryTable[1].Rule.srcPorts.startPort = 0;
	FWEntryTable[1].Rule.srcPorts.endPort = (USHORT)65535;
	FWEntryTable[1].Rule.dstPorts.startPort = 0;
	FWEntryTable[1].Rule.dstPorts.endPort = (USHORT)65535;

	// Ban IPv6
	FWEntryTable[2].Present = 1;
	FWEntryTable[2].Enabled = 1;
	FWEntryTable[2].Rule.id = 2;
	FWEntryTable[2].Rule.name[0] = 'i';
	FWEntryTable[2].Rule.name[1] = 'p';
	FWEntryTable[2].Rule.name[2] = 'v';
	FWEntryTable[2].Rule.name[3] = '6';
	FWEntryTable[2].Rule.name[4] = '\0';
	FWEntryTable[2].Rule.protocol = IPv6;
	FWEntryTable[2].Rule.direction = InOut;
	FWEntryTable[2].Rule.srcMacs.mac[0] = 0;
	FWEntryTable[2].Rule.srcMacs.mac[1] = 0;
	FWEntryTable[2].Rule.srcMacs.mac[2] = 0;
	FWEntryTable[2].Rule.srcMacs.mac[3] = 0;
	FWEntryTable[2].Rule.srcMacs.mac[4] = 0;
	FWEntryTable[2].Rule.srcMacs.mac[5] = 0;
	FWEntryTable[2].Rule.srcMacs.mask[0] = 0;
	FWEntryTable[2].Rule.srcMacs.mask[1] = 0;
	FWEntryTable[2].Rule.srcMacs.mask[2] = 0;
	FWEntryTable[2].Rule.srcMacs.mask[3] = 0;
	FWEntryTable[2].Rule.srcMacs.mask[4] = 0;
	FWEntryTable[2].Rule.srcMacs.mask[5] = 0;
	FWEntryTable[2].Rule.dstMacs.mac[0] = 0;
	FWEntryTable[2].Rule.dstMacs.mac[1] = 0;
	FWEntryTable[2].Rule.dstMacs.mac[2] = 0;
	FWEntryTable[2].Rule.dstMacs.mac[3] = 0;
	FWEntryTable[2].Rule.dstMacs.mac[4] = 0;
	FWEntryTable[2].Rule.dstMacs.mac[5] = 0;
	FWEntryTable[2].Rule.dstMacs.mask[0] = 0;
	FWEntryTable[2].Rule.dstMacs.mask[1] = 0;
	FWEntryTable[2].Rule.dstMacs.mask[2] = 0;
	FWEntryTable[2].Rule.dstMacs.mask[3] = 0;
	FWEntryTable[2].Rule.dstMacs.mask[4] = 0;
	FWEntryTable[2].Rule.dstMacs.mask[5] = 0;
	FWEntryTable[2].Rule.srcIps.version = 4;
	FWEntryTable[2].Rule.dstIps.version = 4;
	FWEntryTable[2].Rule.srcPorts.startPort = 0;
	FWEntryTable[2].Rule.srcPorts.endPort = (USHORT)65535;
	FWEntryTable[2].Rule.dstPorts.startPort = 0;
	FWEntryTable[2].Rule.dstPorts.endPort = (USHORT)65535;

	FILTER_RELEASE_LOCK(&FilterListLock, bFalse);

	DEBUGP(DL_WARN, "Initialize FW Entry Complete!\n");
	return 1;
}
// Load Firewall Entry From Disk
LONG ULoadProfile() {
	HANDLE SourceFileHandle = NULL;      //源文件句柄
	NTSTATUS Status = STATUS_SUCCESS;    //返回状态
	OBJECT_ATTRIBUTES ObjectAttributes;  //OBJECT_ATTRIBUTES结构
	UNICODE_STRING SourceFilePath = RTL_CONSTANT_STRING(PFW_PROFILE_LOCATION); //源文件
	IO_STATUS_BLOCK IoStatusBlock;         //返回结果状态结构体
	LARGE_INTEGER Offset = { 0 };
	FILE_STANDARD_INFORMATION fileInfo = { 0 };

	InitializeObjectAttributes(
		&ObjectAttributes,
		&SourceFilePath,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	Status = ZwCreateFile(
		&SourceFileHandle,
		GENERIC_WRITE | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE |
		FILE_RANDOM_ACCESS |
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (!NT_SUCCESS(Status))
	{
		DEBUGP(DL_ERROR, "Open source file fail !! - %#x\n", Status);
		return 0;
	}
	
	Status = ZwQueryInformationFile(
		SourceFileHandle,
		&IoStatusBlock,
		&fileInfo,
		sizeof(fileInfo),
		FileStandardInformation
	);
	if (!NT_SUCCESS(Status)) {
		ZwClose(SourceFileHandle);
		DEBUGP(DL_ERROR, "Query firewall.bin Information Failed!\n");
		return 0;
	}
	DEBUGP(DL_WARN, "firewall.bin File Size %d, Struct Size %d\n", fileInfo.EndOfFile.LowPart, sizeof(FWEntryTable));
	if (fileInfo.EndOfFile.LowPart != sizeof(FWEntryTable)) {
		ZwClose(SourceFileHandle);
		DEBUGP(DL_ERROR, "firewall.bin File Size Mismatch!\n");
		return 0;
	}
	// read fw entry table to memory
	Status = ZwReadFile(
		SourceFileHandle,
		NULL,
		NULL,
		NULL,
		&IoStatusBlock,
		FWEntryTable,
		sizeof(FWEntryTable),
		&Offset,
		NULL);
	ZwClose(SourceFileHandle);
	if (!NT_SUCCESS(Status))
	{
		DEBUGP(DL_ERROR, "firewall.bin Load Failed!\n");
	}
	return NT_SUCCESS(Status)? 1:0;
}
// Save Firewall Entry To Disk
LONG USaveProfile() {
	HANDLE SourceFileHandle = NULL;      //源文件句柄
	NTSTATUS Status = STATUS_SUCCESS;    //返回状态
	OBJECT_ATTRIBUTES ObjectAttributes;  //OBJECT_ATTRIBUTES结构
	UNICODE_STRING SourceFilePath = RTL_CONSTANT_STRING(PFW_PROFILE_LOCATION); //源文件
	IO_STATUS_BLOCK IoStatusBlock;         //返回结果状态结构体
	LARGE_INTEGER Offset = { 0 };
	InitializeObjectAttributes(
		&ObjectAttributes,
		&SourceFilePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	Status = ZwCreateFile(
		&SourceFileHandle,
		GENERIC_WRITE | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OVERWRITE_IF,
		FILE_NON_DIRECTORY_FILE |
		FILE_RANDOM_ACCESS |
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(Status))
	{
		DEBUGP(DL_ERROR, "Open source file fault !! - %#x\n", Status);
		return 0;
	}
	Status = ZwWriteFile(
		SourceFileHandle,
		NULL,
		NULL,
		NULL,
		&IoStatusBlock,
		FWEntryTable,
		sizeof(FWEntryTable),
		&Offset,
		NULL);
	ZwClose(SourceFileHandle);
	if (!NT_SUCCESS(Status)) {
		DEBUGP(DL_ERROR, "firewall.bin Save Failed!\n");
	}
	DEBUGP(DL_WARN, "firewall.bin Save Success!\n");
	return NT_SUCCESS(Status) ? 1 : 0;
}