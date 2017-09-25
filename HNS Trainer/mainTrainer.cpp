#include "stdafx.h"


#define F1Key 0x70

using namespace std;


// Detectar si un programa está en ejecucion
DWORD getProcessEntry(string processName, PROCESSENTRY32& pentry);
//Conseguir direccion base de un modulo
DWORD_PTR dwGetModuleBaseAddress(DWORD dwProcID, TCHAR *szModuleName);
// TODO? Conseguir direccion de stack del thread0
HANDLE getThread0Handle(DWORD processID);
// Conseguir direccion de una cadena de punteros
DWORD findAddressWithPointers(HANDLE hProc, int PointerLevel, DWORD BaseAddress, DWORD Pointers[]);
// Get the address following pointers of a 64 Process
DWORD_PTR findAddress64WithPointers(HANDLE hProc, int PointerLevel, DWORD_PTR BaseAddress, DWORD offsets[]);
// Funcion para leer memoria
template<typename T>
T readMemory(HANDLE proc, LPVOID adr) {
	T val;
	ReadProcessMemory(proc, adr, &val, sizeof(T), NULL);
	return val;
}
// Funcion para escribir la memoria
template<typename T>
void writeMemory(HANDLE proc, LPVOID adr, T val) {
	WriteProcessMemory(proc, adr, &val, sizeof(T), NULL);
}

template<typename T>
DWORD protectMemory(HANDLE proc, LPVOID adr, DWORD prot) {
	DWORD oldProt;
	VirtualProtectEx(proc, adr, sizeof(T), prot, &oldProt);
	return oldProt;
}


string processName;
PROCESSENTRY32 pe32;
DWORD PID;
HANDLE gameProcesshdl;

// OFFSETS HP 
DWORD offsetsHP[] = { 0x658, 0x1fc, 0x118 };

int _tmain(int argc, _TCHAR* argv[])
{
	processName = "HeartnSlash64.exe";

	// Esta clase consigue información sobre el programa pid, size etc
	SignatureScanner sigscan = SignatureScanner(processName);

	wcout << "--------Heart&Slash TRAINER PLEB VERSION--------" << endl;

	cout << "Comprobando si esta " << processName << " entre los procesos" << endl;

	gameProcesshdl = sigscan.getProcessHandleAndPID();
	

	if (gameProcesshdl != INVALID_HANDLE_VALUE || gameProcesshdl == NULL) {
		if (sigscan.getIs64()) {
			cout << "The process is a 64 Process" << endl;
		}
		else cout << "The process is a 32 Process" << endl;

		PID = sigscan.getPID();

		cout << "se ha econtrado " << processName << ", con PID : " << PID << endl;

		if (!sigscan.findModule64Info("HeartnSlash64.exe")) {
			cout << "ERROR: findModule64Info failed" << endl;
			return 1;
		}

		DWORD_PTR moduleBaseAddress = sigscan.getModule64BaseAddress();
		DWORD moduleSize = sigscan.getSizeofModule();


		wcout << "El proceso se ha cargado en la direccion : " << hex <<  moduleBaseAddress << endl;
		wcout << "Infinite HP" << endl;

		// Calculando la direccion de la HP

		if (moduleBaseAddress != 0) {
			DWORD offsets[] = {0x3E8, 0x448, 0x244};
			
			
			DWORD_PTR addressMEH = moduleBaseAddress + 0x012BFDE8;
			//Its weird cause the first address is 8 bytes but then its 4 bytes
			// for the next addresses and values.
			DWORD addressfirstPointer;
			addressfirstPointer = readMemory<DWORD>(gameProcesshdl, LPVOID(addressMEH));
			DWORD addressHP = findAddressWithPointers(gameProcesshdl, 3, addressfirstPointer, offsets);
			
			wcout << "Address of HP: ";
			wcout << hex << addressHP << endl;
			int gameTime = clock();
			// LOOP
			while (1) {
				if (clock() - gameTime > 100) {
					cout << "Writing to the HP address" << '\r';
					DWORD oldProt;
					BYTE HPvalue = 0x0C; // 12
					oldProt = protectMemory<DWORD>(gameProcesshdl, LPVOID(addressHP), PAGE_READWRITE);
					WriteProcessMemory(gameProcesshdl, LPVOID(addressHP), LPCVOID(&HPvalue), sizeof(HPvalue), NULL);
					
					protectMemory<DWORD>(gameProcesshdl, LPVOID(addressHP), oldProt);
					gameTime = clock();
				}


			}

			system("pause");
			CloseHandle(gameProcesshdl);
			return 0;


		}


	}
	else{
		cout << "No se ha encontrado" << endl;
	}


	CloseHandle(gameProcesshdl);
	system("pause");
	return 0;
}



//Get the base address of the loaded module
DWORD_PTR dwGetModuleBaseAddress(DWORD dwProcID, TCHAR *szModuleName)
{
	DWORD_PTR dwModuleBaseAddress = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcID);
	wcout << "GetLastError()=" << GetLastError() << endl;
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 ModuleEntry32;
		ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnapshot, &ModuleEntry32))
		{
			do
			{

				if (_tcsicmp(ModuleEntry32.szModule, szModuleName) == 0)
				{

					dwModuleBaseAddress = (DWORD_PTR)ModuleEntry32.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnapshot, &ModuleEntry32));
		}
		CloseHandle(hSnapshot);
	}
	return dwModuleBaseAddress;
}



DWORD findAddressWithPointers(HANDLE hProc, int PointerLevel, DWORD BaseAddress, DWORD offsets[]){
	DWORD baseAddress = BaseAddress;
	DWORD tempPointer=baseAddress;
	if (PointerLevel == 1) {
		return tempPointer + offsets[0];
	}
	for (int c = 0; c < PointerLevel; c++) {

		tempPointer = tempPointer + offsets[c];
		
		if (c < PointerLevel - 1) {
			//If not the last then keep reading
			tempPointer = readMemory<DWORD>(hProc, LPVOID(tempPointer));
		}
			
	}
	return tempPointer;
}

//TODO? 64 bit version, not checked not finished
DWORD_PTR findAddress64WithPointers(HANDLE hProc, int PointerLevel, DWORD_PTR BaseAddress, DWORD offsets[]){
	DWORD_PTR baseAddress = BaseAddress;
	DWORD_PTR tempPointer = baseAddress;

	for (int c = 0; c < PointerLevel; c++) {

		tempPointer = tempPointer + offsets[c];
		tempPointer = readMemory<DWORD_PTR>(hProc, LPVOID(tempPointer));
	}
	return readMemory<DWORD_PTR>(hProc, LPVOID(tempPointer));
}

