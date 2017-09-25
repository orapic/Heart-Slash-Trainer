#include "SignatureScanner.h"


using namespace std;

SignatureScanner::SignatureScanner()
{
}

SignatureScanner::SignatureScanner(string processName){
	ProcessName = processName;
	Is64 = false;
}

SignatureScanner::~SignatureScanner()
{
}

DWORD SignatureScanner::getPID(){
	return PID;
}

string SignatureScanner::getProcessName(){
	return ProcessName;
}

DWORD SignatureScanner::getSizeofModule(){
	return SizeofModule;
}

DWORD SignatureScanner::getModuleBaseAddress(){
	return ModuleBaseAddress;
}

BOOLEAN SignatureScanner::getIs64(){
	return Is64;
}

DWORD_PTR SignatureScanner::getModule64BaseAddress(){
	return Module64BaseAddress;
}

BOOLEAN SignatureScanner::findModuleInfo(string moduleName) {
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;
	//wstring moduleNametemp = wstring(moduleName.begin(), moduleName.end());
	//LPCWSTR moduleNametempL = moduleNametemp.c_str();
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		cout << "CreateToolhelp32Snapshot (of modules)" << endl;
		return false;
	}

	me32.dwSize = sizeof(MODULEENTRY32);

	//  Retrieve information about the first module, 
	//  and exit if unsuccessful 
	if (!Module32First(hModuleSnap, &me32))
	{
		cout << "Module32First" << endl;  // Show cause of failure 
		CloseHandle(hModuleSnap);     // Must clean up the snapshot object! 
		return(FALSE);
	}

	do {
		string moduleUName(me32.szModule);
		if (moduleUName.compare(moduleName) == 0) {
			ModuleBaseAddress = (DWORD)me32.modBaseAddr;
			SizeofModule = me32.modBaseSize;
			wcout << "Encontrada la handle del module: " << me32.hModule << endl;
			cout << "Dirección del module: " << std::hex <<  ModuleBaseAddress << endl;
			cout << "Tamaño del module: " << std::hex << SizeofModule << endl;
			return true;
		}
	} while (Module32Next(hModuleSnap, &me32));

	return false;

}

BOOLEAN SignatureScanner::findModule64Info(string moduleName) {
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		cout << "ERROR: CreateToolhelp32Snapshot (of modules). GetLastError: 0x" << hex << GetLastError() << endl;
		return false;
	}

	me32.dwSize = sizeof(MODULEENTRY32);

	//  Retrieve information about the first module, 
	//  and exit if unsuccessful 
	if (!Module32First(hModuleSnap, &me32))
	{
		cout << "ERROR: Module32First" << endl;  // Show cause of failure 
		CloseHandle(hModuleSnap);     // Must clean up the snapshot object! 
		return(FALSE);
	}

	do {
		string moduleUName(me32.szModule);
		if (moduleUName.compare(moduleName) == 0) {
			//Need to use a DWORD_PTR for a 64 bit module
			Module64BaseAddress = (DWORD_PTR)me32.modBaseAddr;
			SizeofModule = me32.modBaseSize;
			wcout << "Encontrada la handle del module: " << me32.hModule << endl;
			cout << "Dirección del module: " << std::hex << Module64BaseAddress << endl;
			cout << "Tamaño del module: " << std::hex << SizeofModule << endl;
			return true;
		}
	} while (Module32Next(hModuleSnap, &me32));
	cout << "Module not found" << endl;
	return false;

}


HANDLE SignatureScanner::getProcessHandleAndPID(){
	HANDLE hProcessSnap;
	PROCESSENTRY32 pentry;
	pentry.dwSize = sizeof(PROCESSENTRY32);
	BOOLEAN procesoEncontrado = false;

	wstring processNametemp = wstring(ProcessName.begin(), ProcessName.end());
	LPCWSTR pprocessNametemp = processNametemp.c_str();
	
	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("CreateToolhelp32Snapshot (of processes)"));
		return(FALSE);
	}

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pentry))
	{
		_tprintf(TEXT("Process32First")); // show cause of failure
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return(FALSE);
	}
	do {
		size_t size = strlen(pentry.szExeFile) + 1;
		wchar_t* wchart = new wchar_t[size];
		size_t outSize;
		mbstowcs_s(&outSize, wchart, size, pentry.szExeFile, size-1);
		LPWSTR ptr = wchart;
		if (lstrcmpiW(ptr, pprocessNametemp) == 0) {
			procesoEncontrado = true;
			PID = pentry.th32ProcessID;
			
			// Code to know if a process is either 32 or 64
			// First we need to know if the system is 32 or 64
			HANDLE processHandle;
			_SYSTEM_INFO systemInfo;
			GetNativeSystemInfo(&systemInfo);
			BOOL piswow64;

			processHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, PID);
			if(systemInfo.wProcessorArchitecture == 0) {
				// 32 bit system
				 Is64=false;
				}
			else {
				//64 bit system
				if (IsWow64Process(processHandle, &piswow64) != 0) {
					if (piswow64) {
						// 32 bit process running in 64 system
						Is64 = false;
					}
					else {
						// 64 bit process running in 64 system
						Is64 = true;
					}
				}
			}
			return  processHandle;
			
		}


	} while (!procesoEncontrado && Process32Next(hProcessSnap, &pentry));

	return INVALID_HANDLE_VALUE;

}