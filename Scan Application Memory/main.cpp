#include"MemScan.h"

/*	Scan the memory space of active applications on x86 Windows 8.1
 *	
 *	The following steps must be performed to accomplish the goal:
 *	1.	Obtain a process handle
 *	2.	Get the process address range
 *	3.	Examine the memory range
 *	4.	Dump the memory
 */

/*fuck source control*/

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <string>

#ifndef UNICODE  
typedef std::string String;
#else
typedef std::wstring String;
#endif

void PrintModules(DWORD processID, std::ofstream &outfile, unsigned long long &lpMem, unsigned long long &lpModuleBound);
int ModifyTokenPrivileges(char*);
void MemWalk(DWORD processID, unsigned long long startAddr, void * endAddr, std::ofstream &outfile);

int main(int argc, char *argv[]){
	DWORD winapiErr = NULL;
	HANDLE hProcess = NULL;
	DWORD processID = 8972;
	unsigned long long lpMem = 0;
	unsigned long long lpModuleBoundary = 0;
	std::vector<byte> memory_dump;
	std::ofstream outfile;

	outfile.open("mem_dump.txt");
	
	std::cout << processID << std::endl;

	// Give this process debug pivileges
	if (!ModifyTokenPrivileges(SE_DEBUG_NAME)){
		exit(1);
	}

	PrintModules(processID, outfile, lpMem, lpModuleBoundary);

	std::cout << "begin memwalk\n";
	MemWalk(processID, lpMem, (LPVOID)lpModuleBoundary, outfile);
	std::cout << "DONE!" << std::endl;
	outfile.close();
	CloseHandle(hProcess);
	return 0;
}

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

void PrintModules(DWORD processID, std::ofstream &outfile, unsigned long long &lpMem, unsigned long long &lpModuleBound)
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

  if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)){
    for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++){
      TCHAR szModName[MAX_PATH];

      // Get the full path to the module's file.

      if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
        sizeof(szModName) / sizeof(TCHAR))){
        _tprintf(TEXT("%s (0x%08X)\n"), szModName, (unsigned long long)hMods[i]);

        outfile << szModName << " (0x" << std::setw(8) << std::setbase(16) << (unsigned long long)hMods[i];
        outfile << ")\n";
        if ((std::string)szModName == "C:\\WINDOWS\\system32\\notepad.exe"){
          lpMem = (unsigned long long) hMods[i];
          lpModuleBound = (unsigned long long) hMods[i + 1];
        }
      }
    }
  } else {
    std::cerr << "OpenProcessToken() failed with code: " << GetLastError() << std::endl;
  }

  // Release the handle to the process.
  CloseHandle(hProcess);
}

int ModifyTokenPrivileges(char* priv)
{
  HANDLE hToken = NULL;
  TOKEN_PRIVILEGES tPrivileges;
  LUID luid;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)){
    std::cerr << "OpenProcessToken() failed with code: " << GetLastError() << std::endl;
    return 0;
  }
  if (!LookupPrivilegeValue(NULL, priv, &luid)){
    std::cerr << "LookupPrivilegeValue() failed with code: " << GetLastError() << std::endl;
    return 0;
  }

  tPrivileges.PrivilegeCount = 1;
  tPrivileges.Privileges[0].Luid = luid;
  tPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!AdjustTokenPrivileges(hToken, FALSE, &tPrivileges, NULL, NULL, NULL)){
    std::cerr << "AdjustTokenPrivileges() failed with code: " << GetLastError() << std::endl;
    return 0;
  }
  if (!CloseHandle(hToken)){
    std::cerr << "CloseHandle() failed with code: " << GetLastError() << std::endl;
    return 0;
  }
  return 1;
}

void MemWalk(DWORD pid, unsigned long long startAddr, void * endAddr, std::ofstream &outfile) {
  HANDLE hProcess;
  DWORD winapiErr;
  SIZE_T lpBytesRead = 0;
  SYSTEM_INFO si;
  std::vector<byte> chunk;
  MEMORY_BASIC_INFORMATION mbi;
  DWORD flOldProtect;
  DWORD unallocated;

  // get process handle
  hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (hProcess == NULL) {
    winapiErr = GetLastError();
    std::cout << "OpenProcess() failed with code: " << winapiErr << std::endl;
    exit(winapiErr);
  }

  GetSystemInfo(&si);
  chunk.resize(si.dwPageSize);
  while ((LPVOID)startAddr < si.lpMaximumApplicationAddress) {

    if (!VirtualQueryEx(hProcess, (LPVOID)startAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
      winapiErr = GetLastError();
      std::cout << "VirtualQueryEx() failed with code: " << winapiErr << std::endl;
	  while (1);
      exit(winapiErr);
    }

	if ((mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_GUARD) && mbi.State != MEM_FREE) {

	if (!VirtualProtectEx(hProcess, (LPVOID)startAddr, si.dwPageSize, PAGE_EXECUTE_READWRITE, &flOldProtect)) {
		winapiErr = GetLastError();
		std::cout << "VirtualProtectEx() failed with code: " << winapiErr << std::endl;
		while (1);
		exit(winapiErr);
	}

	}

	if (mbi.State != MEM_FREE) {
	if(!ReadProcessMemory(hProcess, (LPCVOID)startAddr, (LPVOID)&chunk[0], si.dwPageSize, &lpBytesRead)) {
		winapiErr = GetLastError();
		std::cout << "ReadProcessMemory() failed with code: " << winapiErr << std::endl;
		while (1);
		exit(winapiErr);
	}
	}

	//if (!VirtualProtectEx(hProcess, (LPVOID)startAddr, si.dwPageSize, flOldProtect, NULL)) {
	//	winapiErr = GetLastError();
	//	std::cout << "VirtualProtectEx() failed with code: " << winapiErr << std::endl;
	//	exit(winapiErr);
	//}

    for (int j = 0; j < lpBytesRead; ++j) {
      for (int i = 0; i < 64 && j < lpBytesRead; ++i) {
        std::cout << chunk[j];
        outfile << std::setw(2) << std::setbase(16) << chunk[j++];
      }
      std::cout << std::endl;
      outfile << std::endl;
    }
	startAddr += lpBytesRead;
  }
}