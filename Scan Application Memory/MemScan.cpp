#include"MemScan.h"

#include <string>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <iostream>
#include <iomanip>
#include <fstream>

#ifndef UNICODE  
typedef std::string String;
#else
typedef std::wstring String;
#endif

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

void MemScan::PrintModules(DWORD processID, std::ofstream &outfile, unsigned long long &lpMem, unsigned long long &lpModuleBound)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Get a handle to the process.

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);
	if (NULL == hProcess)
		return;

	// Get a list of all the modules in this process.

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				_tprintf(TEXT("%s (0x%08X)\n"), szModName, (unsigned long long)hMods[i]);
				
				outfile << szModName << " (0x" << std::setw(8) << std::setbase(16) << (unsigned long long)hMods[i];
				outfile << ")\n";
				if ((std::string)szModName == "F:\\Users\\Mitch\\Downloads\\Fusion364\\Fusion364\\Fusion.exe")
				{
					lpMem = (unsigned long long) hMods[i];
					lpModuleBound = (unsigned long long) hMods[i + 1];
				}
			}
		}
	}
	else 
	{
		std::cerr << "OpenProcessToken() failed with code: " << GetLastError() << std::endl;
	}

	// Release the handle to the process.
	CloseHandle(hProcess);
}

int MemScan::ModifyTokenPrivileges(char* priv)
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tPrivileges;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		std::cerr << "OpenProcessToken() failed with code: " << GetLastError() << std::endl;
		return 0;
	}
	if (!LookupPrivilegeValue(NULL, priv, &luid))
	{
		std::cerr << "LookupPrivilegeValue() failed with code: " << GetLastError() << std::endl;
		return 0;
	}
	tPrivileges.PrivilegeCount = 1;
	tPrivileges.Privileges[0].Luid = luid;
	tPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tPrivileges, NULL, NULL, NULL))
	{
		std::cerr << "AdjustTokenPrivileges() failed with code: " << GetLastError() << std::endl;
		return 0;
	}
	if (!CloseHandle(hToken))
	{
		std::cerr << "CloseHandle() failed with code: " << GetLastError() << std::endl;
		return 0;
	}
	return 1;
}

std::vector<byte> MemScan::MemWalk(DWORD processID, void *startAddr, unsigned long long readLength)
{
	HANDLE hProcess;
	unsigned long winapiErr;
	unsigned long long *lpBytesRead = 0;

	std::vector<byte> memDump;
	MEMORY_BASIC_INFORMATION memBasicInfo;

	// get process handle
	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, processID);
	if (hProcess == NULL)
	{
		winapiErr = GetLastError();
		std::cout << "OpenProcess() failed with code: " << winapiErr << std::endl;
		exit(winapiErr);
	}
	memBasicInfo = GetMbi(processID, startAddr);

	memDump.resize(readLength);
	ReadProcessMemory(hProcess, startAddr, &memDump[0], readLength, (SIZE_T *)lpBytesRead);

	return memDump;
}

MEMORY_BASIC_INFORMATION MemScan::GetMbi(DWORD processID, void *startAddr)
{
	HANDLE hProcess;
	unsigned long long winapiErr;
	MEMORY_BASIC_INFORMATION memBasicInfo;
	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, processID);
	if (hProcess == NULL)
	{
		winapiErr = GetLastError();
		std::cout << "OpenProcess() failed with code: " << winapiErr << std::endl;
		exit(winapiErr);
	}

	if (!VirtualQueryEx(hProcess, startAddr, &memBasicInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		winapiErr = GetLastError();
		std::cout << "VirtualQueryEx() failed with code: " << winapiErr << std::endl;
		exit(winapiErr);
	}
	return memBasicInfo;
}