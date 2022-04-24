#include <strsafe.h>
#include <Windows.h>
#include <iostream>
#include "main.h"

using namespace std;

constexpr auto SIOCTL_TYPE = 40000;
constexpr auto IOCTL_SIOCTL_METHOD_BUFFERED = CTL_CODE(SIOCTL_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS);

// inputBuffer:         pointer to input buffer
// inputBufferSize:     input buffer size, counted in bytes
// outputBuffer:        pointer to output buffer
// outputBufferSize:    output buffer size, counted in bytes
// bytesReturned:       number of bytes received from device
//
// return:              success(true), fail(false)
bool syncDeviceIoBuffer(
	LPVOID inputBuffer,
	DWORD inputBufferSize,
	LPVOID outputBuffer,
	DWORD outputBufferSize,
	DWORD& bytesReturned
) {
	HANDLE hDevice = CreateFile(
		L"\\\\.\\NDISLWF",
		GENERIC_READ | GENERIC_WRITE,
		0,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);

	if (hDevice == INVALID_HANDLE_VALUE) {
		const DWORD errorCode = GetLastError();
		printf("CreateFile failed, error code: %lu\n", errorCode);
		return false;
	}

	// Performing METHOD_BUFFERED

	const BOOL success = DeviceIoControl(
		hDevice,
		static_cast<DWORD>(IOCTL_SIOCTL_METHOD_BUFFERED),
		inputBuffer,
		inputBufferSize,
		outputBuffer,
		outputBufferSize,
		&bytesReturned,
		nullptr
	);

	if (!success) 
		printf("Error in DeviceIoControl : %lu\n", GetLastError());
	CloseHandle(hDevice);
	return success;
}

const int inputSize = sizeof(FWEntryTable) * 2, outputSize = sizeof(FWEntryTable) * 2;
CHAR inputBuffer[inputSize], outputBuffer[outputSize];

int listStatus() {
	for (int i = 0; i < RULE_MAX_LENGTH; i++)
	{
		if (!FWEntryTable[i].Present)continue;
		cout << "Rule " << FWEntryTable[i].Rule.id << " :\t";
		// cout << (FWEntryTable[i].Present ? "Valid" : "None") << "\t";
		cout << (FWEntryTable[i].Enabled ? "Enabled" : "Disabled") << '\t';
		cout << FWEntryTable[i].Statistic;
		cout << endl;
	}
}
int listRuleIndex(int index) {
	
	cout << "Valid     : " << (FWEntryTable[index].Present ? "Yes" : "No") << endl;
	cout << "Enabled   : " << (FWEntryTable[index].Enabled ? "Yes" : "No") << endl;
	cout << "Statistic : " << FWEntryTable[index].Statistic << endl;
	cout << "Id        : " << FWEntryTable[index].Rule.id << endl;
	cout << "Name      : " << FWEntryTable[index].Rule.name << endl;
	cout << "Direction : " << (FWEntryTable[index].Rule.direction & In ? "In": "_")
		<< (FWEntryTable[index].Rule.direction & Out ? "Out" : "_") << endl;
	cout << "Protocol  : ";
	if (0 <= FWEntryTable[index].Rule.protocol && FWEntryTable[index].Rule.protocol <= UDP) cout << ProtocalName[FWEntryTable[index].Rule.protocol];
	else cout << "InValid";
	cout << endl;

}

int __cdecl main(
	_In_ ULONG argc,
	_In_reads_(argc) PCHAR argv[]
) {
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);
	char temp[inputSize] = {};
	DWORD returned;
	char* pEntry, * pBuffer;
	while (true) {
		char a;
		cin >> a;
		switch(a) {
		case 'd':
			temp[0] = 0;		// mode 0: fetch table

			syncDeviceIoBuffer(temp, inputSize, temp, outputSize, returned);

			// Returned Data:
			// [0] :						success(1) or fail(0)
			// [1, sizeof(FWEntryTable)] :	FWEntryTable
			cout << "status\t" << int(temp[0]) << endl;
			cout << "returned\t" << returned << endl;

			pBuffer = temp + 1;
			pEntry = (char*)FWEntryTable;
			for (int i = 0; i < sizeof(FWEntryTable); i++)
			{
				*pEntry = *pBuffer;
				pEntry++;
				pBuffer++;
			}
			// print
			pEntry = (char*)FWEntryTable;
			for (int i = 0; i < sizeof(FWEntryTable); i++)
			{
				cout << hex << int(*pEntry);
				pEntry++;
			}
			cout << endl;
			break;
		case 'e':
			temp[0] = 1;		// mode 1: set table

			pBuffer = temp + 1;
			pEntry = (char*)FWEntryTable;
			for (int i = 0; i < sizeof(FWEntryTable); i++)
			{
				*pBuffer = *pEntry;
				pEntry++;
				pBuffer++;
			}

			syncDeviceIoBuffer(temp, inputSize, temp, outputSize, returned);

			// Returned Data:
			// [0] : success(1) or fail(0)
			cout << "status\t" << int(temp[0]) << endl;
			cout << "returned\t" << returned << endl;
			break;
		default:
			cout << "Op Not Allowed!" << endl;
			break;
		}
	}
	return 0;
}

