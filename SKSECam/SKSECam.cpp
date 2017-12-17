/*                             The MIT License (MIT)

Copyright (c) 2016 Sumwunn @ github.com

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.*/

#include "stdafx.h"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <string>

// Defined functions.
// ASM
extern "C" void* BinSearch(void* Search, int SearchLength, unsigned char* Bytes, int BytesLength, int AddMod, int SubMod);


//Analyse the code and patch it so it call our asm hooking function
//This is done because there is no code cave available in Skyrim memory
extern "C" void Container_ApplyHook(void* Adress);


// Work around because my ASM function GetTextSectionData has multiple return value data types.
extern "C" void* GetTextSectionAddr(HMODULE Module, int DataType);
extern "C" int GetTextSectionSize(HMODULE Module, int DataType);
// C++
int BinPatch(HMODULE hModule, unsigned char* BytesToFind, int BytesToFindSize, unsigned char* BytesPatch, int BytesPatchSize, int AddressModifierAdd, int AddressModifierSub);





// Return values
// 0 = Patching failed, bytes not found.
// 1 = Patching successful, bytes found.
// -1 = Process is NOT expected target.
// -2 = Log file creation failed.
extern "C" __declspec(dllexport) int Setup()

{


	LPCTSTR ExpectedProcess02 = L"SkyrimSE.exe";


	unsigned char SaveGameTimePatternToFind_01[] = { 0x0F ,0xB7, 0x4C, 0x24, 0x30,
		0xB8, 0x1F, 0x85, 0xEB, 0x51,
		0x44, 0x0F, 0xB7, 0x4C, 0x24, 0x36 ,
		0x44, 0x0F, 0xB7, 0x44, 0x24, 0x32 };


	unsigned char SaveGameTimePatch_01[] = { 0x0F ,0xB7, 0x4C, 0x24, 0x30,
		0xB8, 0x1F, 0x85, 0xEB, 0x51,
		0x44, 0x0F, 0xB7, 0x44, 0x24, 0x36 ,
		0x44, 0x0F, 0xB7, 0x4C, 0x24, 0x32 };

	unsigned char SaveGameTimePatch_02[] = { 0x90,0x90 };


	//////// Setup Part 1 - Config ////////

	TCHAR ConfigFilePath[MAX_PATH];
	int iEnableLogging = 1;
	// 0 = Disable.
	// 1 = Enable.


	// Get config path.
	GetCurrentDirectory(MAX_PATH, ConfigFilePath);
	_tcscat_s(ConfigFilePath, MAX_PATH, L"\\Data\\SKSE\\Plugins\\SKSECam.ini");

	// Get config settings.
	iEnableLogging = GetPrivateProfileInt(L"General", L"iEnableLogging", 1, ConfigFilePath);


	// Checking for incorrect values.
	if (iEnableLogging < 0 || iEnableLogging > 1)
	{
		iEnableLogging = 1;
	}
	

	// Misc.
	HMODULE hModule = NULL;
	std::ofstream LogFileHandle;

	//////// Setup Part 2 - Addresses & Logging ////////

	if (iEnableLogging == 1)
	{
		LogFileHandle.open(L"Data\\SKSE\\Plugins\\SKSECam.log");

		// Log file creation failed.
		if (!LogFileHandle)
		{
			return -2;
		}
	}


	// Skyrim SE.
	hModule = GetModuleHandle(ExpectedProcess02);

	if (hModule != NULL)
	{

		//Common : Récupère des informations sur le processus

		void* _PatchAddress = (void*)NULL;
		void* _SearchAddress = (void*)NULL;
		int _SearchSize = NULL;
		DWORD _lpflOldProtect = NULL;

		_SearchSize = GetTextSectionSize(hModule, 1);
		_SearchAddress = GetTextSectionAddr(hModule, 2);



//1 ) Patch 1 => Format de date sur les écrans de sauvegarde

/*
00007FF60395915D | 0F B7 4C 24 30           | movzx ecx,word ptr ss:[rsp+30]          |
00007FF603959162 | B8 1F 85 EB 51           | mov eax,51EB851F                        |
00007FF603959167 | 44 0F B7 4C 24 36        | movzx r9d,word ptr ss:[rsp+36]          |
00007FF60395916D | 44 0F B7 44 24 32        | movzx r8d,word ptr ss:[rsp+32]          |
00007FF603959173 | F7 E9                    | imul ecx                                |
00007FF603959175 | C1 FA 05                 | sar edx,5                               |
00007FF603959178 | 8B C2                    | mov eax,edx                             |
00007FF60395917A | C1 E8 1F                 | shr eax,1F                              |
00007FF60395917D | 03 D0                    | add edx,eax                             |
00007FF60395917F | 6B C2 64                 | imul eax,edx,64                         |
00007FF603959182 | 48 8D 15 6F 12 E0 00     | lea rdx,qword ptr ds:[7FF60475A3F8]     | 0x00007FF60475A3F8:"%d/%d/%d"
00007FF603959189 | 2B C8                    | sub ecx,eax                             |


PATCH

00007FF60395915D | 0F B7 4C 24 30           | movzx ecx,word ptr ss:[rsp+30]          |
00007FF603959162 | B8 1F 85 EB 51           | mov eax,51EB851F                        |
00007FF603959167 | 44 0F B7 44 24 36        | movzx r8d,word ptr ss:[rsp+36]          | <<Inversion des registres
00007FF60395916D | 44 0F B7 4C 24 32        | movzx r9d,word ptr ss:[rsp+32]          | <<Inversion des registres
00007FF603959173 | F7 E9                    | imul ecx                                |
00007FF603959175 | C1 FA 05                 | sar edx,5                               |
00007FF603959178 | 8B C2                    | mov eax,edx                             |
00007FF60395917A | C1 E8 1F                 | shr eax,1F                              |
00007FF60395917D | 03 D0                    | add edx,eax                             |
00007FF60395917F | 6B C2 64                 | imul eax,edx,64                         |
00007FF603959182 | 48 8D 15 6F 12 E0 00     | lea rdx,qword ptr ds:[7FF60475A3F8]     | 0x00007FF60475A3F8:"%d/%d/%d" (addr+0x2C)
00007FF603959189 | 90 90                    | nop nop                                |
*/


		int result = 0;

		result = BinPatch(hModule, SaveGameTimePatternToFind_01, sizeof(SaveGameTimePatternToFind_01), SaveGameTimePatch_01, sizeof(SaveGameTimePatch_01), NULL, NULL);

		if (result == 0)
		{
			if (iEnableLogging == 1)
			{

				LogFileHandle << "Erreur : impossible de  patcher la date" << std::endl;
				
			}
		}
		else
		{

			BinPatch(hModule, SaveGameTimePatch_01, sizeof(SaveGameTimePatch_01), SaveGameTimePatch_02, sizeof(SaveGameTimePatch_02), 0x2C, NULL);
			if (iEnableLogging == 1)
			{

				LogFileHandle << "Patch de la date OK :)" << std::endl;
			
			}

		}

		
		unsigned char ContainerBytepattern_01[] = { 0xF6, 0xC1,0x01 ,0x74 ,0x37 ,0x4D ,0x85 ,0xFF ,0x74 ,0x32 ,0x49 ,0x8B ,0xCF,0xE8 };

		_PatchAddress = BinSearch(_SearchAddress, _SearchSize, ContainerBytepattern_01, sizeof(ContainerBytepattern_01), NULL, NULL);

		if (_PatchAddress != NULL)
		{

			LogFileHandle << "Patch des conteneurs..." << std::endl;

			VirtualProtect(_PatchAddress, 0x100, PAGE_EXECUTE_READWRITE, &_lpflOldProtect);

			Container_ApplyHook(_PatchAddress);

			VirtualProtect(_PatchAddress, 0x100, _lpflOldProtect, &_lpflOldProtect);

		}


	

		if (iEnableLogging == 1)
		{
			LogFileHandle.close();
		}




	}
	else //SkyrimSE non lancé? ???
	{

		if (iEnableLogging == 1)
		{

			LogFileHandle << "SkyrimSE.exe non détecté." << std::endl;
			LogFileHandle.close();
		}
		return -1;
	}
	return 0;
}




int BinPatch(HMODULE hModule, unsigned char* BytesToFind, int BytesToFindSize, unsigned char* BytesPatch, int BytesPatchSize, int AddressModifierAdd, int AddressModifierSub) // BinSearch + MEMCPY patching.
{
	// The address we get from GetTextSectionAddr.
	void* SearchAddress = (void*)NULL;
	// The size too.
	int SearchSize = NULL;
	// The address we get from BinSearch.
	void* PatchAddress = (void*)NULL;
	// Misc.
	DWORD lpflOldProtect = NULL;

	// Get size and address of ExpectedProcess's .text section.
	SearchSize = GetTextSectionSize(hModule, 1);
	SearchAddress = GetTextSectionAddr(hModule, 2);
	// Get address and patch it.
	PatchAddress = BinSearch(SearchAddress, SearchSize, BytesToFind, BytesToFindSize, AddressModifierAdd, AddressModifierSub);
	if (PatchAddress == NULL)
	{
		// Bytes not found.
		return 0;
	}
	// Bytes found!
	else
	{
		// Patch it! (with NOPS)
		VirtualProtect(PatchAddress, BytesPatchSize, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
		memcpy(PatchAddress, BytesPatch, BytesPatchSize);
		VirtualProtect(PatchAddress, BytesPatchSize, lpflOldProtect, &lpflOldProtect);
		return 1;
	}

	return 0;
}

#ifdef _SKSE64_
////// SKSE64 //////
#include "common\IPrefix.h"
#include "skse64\PluginAPI.h"

extern "C" __declspec(dllexport) bool SKSEPlugin_Query(const SKSEInterface * skse, PluginInfo * info)
{
	info->infoVersion = PluginInfo::kInfoVersion;
	info->name = "SKSECam";
	info->version = 1;

	return TRUE;
}

extern "C" __declspec(dllexport) bool SKSEPlugin_Load(const SKSEInterface * skse)
{
	Setup();

	return TRUE;
}
#endif