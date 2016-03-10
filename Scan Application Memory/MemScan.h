#ifndef MEMSCAN_H
#define MEMSCAN_H

#include <windows.h>
#include <string>
#include <fstream>
#include <vector>

class MemScan {
public:
	void PrintModules(DWORD processID, std::ofstream &outfile, unsigned long long &lpMem, unsigned long long &lpModuleBound);
	int ModifyTokenPrivileges(char*);
	std::vector<byte> MemWalk(DWORD processID, void* starAddr, unsigned long long readLength);
	MEMORY_BASIC_INFORMATION MemScan::GetMbi(DWORD processID, void *startAddr);
};

#endif