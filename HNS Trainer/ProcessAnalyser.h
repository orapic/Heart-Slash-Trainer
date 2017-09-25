#pragma once
#include "stdafx.h"

using namespace std;

class ProcessAnalyser
{
public:
	//Default Constructor
	ProcessAnalyser();
	//Overload 
	ProcessAnalyser(string processName);
	~ProcessAnalyser();
	
	// Consigue un Handle del proceso y su PID
	HANDLE getProcessHandleAndPID();

	//Getter del PID
	DWORD getPID();

	//Getter del Nombre del proceso
	string getProcessName();

	//Getter del Tamaño del Module
	DWORD getSizeofModule();

	//Getter del Base Address del Module 32 bits
	DWORD getModuleBaseAddress();

	//Getter for the Base Address of the 64 module
	DWORD_PTR getModule64BaseAddress();

	// Conseguir el tamaño y handle para el modulo
	BOOLEAN findModuleInfo(string moduleName);

	// Get size and handle of Module 64
	BOOLEAN findModule64Info(string moduleName);

	BOOLEAN getIs64();
private: 
	//Name of the process
	string ProcessName;
	// Handle of the process
	HANDLE ProcessHandle;
	// PID 
	DWORD PID;
	// Base address of Module
	DWORD ModuleBaseAddress;
	// Base address of 64 bit Module
	DWORD_PTR Module64BaseAddress;
	// Size of Module shared between 32 and 64 modules
	DWORD SizeofModule;
	// Bool: TRUE=64, FALSE=32
	BOOLEAN Is64;

};

