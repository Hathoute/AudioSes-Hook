// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <cstdint>
#include <cstdlib>


typedef HRESULT(*PFGetBuffer) (
    UINT32 NumFramesRequested,
    BYTE** ppData
    );

typedef HRESULT(*PFReleaseBuffer) (
    UINT32 NumFramesWritten,
    DWORD  dwFlags
    );

typedef void (*PFPostGetBuffer)();

typedef struct tWAVEFORMATEX {
    WORD  wFormatTag;
    WORD  nChannels;
    DWORD nSamplesPerSec;
    DWORD nAvgBytesPerSec;
    WORD  nBlockAlign;
    WORD  wBitsPerSample;
    WORD  cbSize;
} WAVEFORMATEX, * PWAVEFORMATEX, * NPWAVEFORMATEX, * LPWAVEFORMATEX;

typedef void IAudioClient;

typedef HRESULT(__stdcall* PFGetMixFormat)(
    IAudioClient* _this, WAVEFORMATEX** ppDeviceFormat
    );

typedef HRESULT(__stdcall* PFStart)();

BOOL initialized = FALSE;
HANDLE hWaveMem = NULL, hDataMem = NULL;
DWORD *waveMemPtr = nullptr, *dataMemPtr = nullptr;
size_t szDataAllocated = 0;
HANDLE hPipe = NULL;

PFGetBuffer OriginalGetBuffer = nullptr;
PFReleaseBuffer OriginalReleaseBuffer = nullptr;
PFPostGetBuffer OriginalPostGetBuffer = nullptr;
PFGetMixFormat OriginalGetMixFormat = nullptr;
PFStart OriginalStart = nullptr;

long long getBufferFrame = 0;
long long releaseBufferFrame = 0;
IAudioClient* audioClientPtr = nullptr;

BYTE** dataPtrPtr = nullptr;
BYTE* dataPtr = nullptr;
WAVEFORMATEX* waveformatPtr = nullptr;

void SetupJumpInstructionBytes(uint8_t* jmpInstruction, uintptr_t jumpStartAddress, uintptr_t addressToJumpTo)
{
    const uintptr_t x86FixedJumpSize = 5;
    uintptr_t relativeAddress = addressToJumpTo - jumpStartAddress - x86FixedJumpSize;
    jmpInstruction[0] = 0xE9; // jump opcode
    *(uintptr_t*)&jmpInstruction[1] = relativeAddress;
}

void PlaceJumpToAddress(uintptr_t installAddress, uintptr_t addressToJumpTo)
{
    uint8_t jmpInstruction[5];
    SetupJumpInstructionBytes(jmpInstruction, installAddress, addressToJumpTo);
    DWORD dwProtect[2];
    VirtualProtect((void*)installAddress, 5, PAGE_EXECUTE_READWRITE, &dwProtect[0]);
    memcpy((void*)installAddress, jmpInstruction, 5);
    VirtualProtect((void*)installAddress, 5, dwProtect[0], &dwProtect[1]);
}

uintptr_t HookFunction(uintptr_t targetAddress, uintptr_t HookFunctionAddress, uint32_t hookSize)
{
    // setup the trampoline
    uintptr_t trampolineAddress = (uintptr_t)VirtualAlloc(0, hookSize + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy((void*)trampolineAddress, (void*)targetAddress, hookSize);

    // place a jump at the bottom of the bytes, so we can go back to the original function
    uintptr_t jumpAddress = trampolineAddress + hookSize;
    uint8_t jmpInstruction[5];
    SetupJumpInstructionBytes(jmpInstruction, jumpAddress, targetAddress + hookSize);
    memcpy((void*)jumpAddress, jmpInstruction, 5);

    // The trampoline is done. Now we place a jump in the target function to redirect the 
    // call to our custom function
    PlaceJumpToAddress(targetAddress, HookFunctionAddress);

    // Check if hookSize is greater than 5, if so set NOP
	if(hookSize > 5) {
        uint8_t* nopCodes = (uint8_t*)malloc(sizeof(uint8_t) * (hookSize - 5));
		for(size_t i = 0; i < hookSize - 5; i++) {
            nopCodes[i] = 0x90;
		}

        DWORD dwProtect[2];
        VirtualProtect((void*)(targetAddress + 5), hookSize - 5, PAGE_EXECUTE_READWRITE, &dwProtect[0]);
        memcpy((void*)(targetAddress + 5), nopCodes, hookSize - 5);
        VirtualProtect((void*)(targetAddress + 5), hookSize - 5, dwProtect[0], &dwProtect[1]);
	}
	
    return trampolineAddress;
}

DWORD CreateNewShared(LPCWSTR name, DWORD bufSize, HANDLE* hMapFilePtr, DWORD** buffPtrPtr) {
    *hMapFilePtr = CreateFileMapping(
        INVALID_HANDLE_VALUE,    // use paging file
        NULL,                    // default security
        PAGE_READWRITE,          // read/write access
		0,                 // maximum object size (high-order DWORD)
        bufSize,                  // maximum object size (low-order DWORD)
        name);                  // name of mapping object

    if (*hMapFilePtr == NULL) {
        return GetLastError();
    }

    *buffPtrPtr = (DWORD*)MapViewOfFile(*hMapFilePtr,   // handle to map object
        FILE_MAP_ALL_ACCESS, // read/write permission
        0,
        0,
        bufSize);
	
    if (*buffPtrPtr == NULL) {
        CloseHandle(*hMapFilePtr);
        *hMapFilePtr = NULL;
        return GetLastError();
    }

    /*SetSecurityInfo(*hMapFilePtr, SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL, NULL, NULL, NULL);*/
	
    return 0;
}

DWORD CreateShared(LPCWSTR name, DWORD bufSize, HANDLE* hMapFilePtr, DWORD** buffPtrPtr) {
    if (*hMapFilePtr != NULL) {
        UnmapViewOfFile(*buffPtrPtr);
        CloseHandle(*hMapFilePtr);
    }

	return CreateNewShared(name, bufSize, hMapFilePtr, buffPtrPtr);
}

void OnWaveFormatChanged() {
	if(!initialized) {
        return;
	}

    CopyMemory(waveMemPtr, waveformatPtr, sizeof(WAVEFORMATEX));

    DWORD dataToSend[2], written;
    dataToSend[0] = 0x1;
    dataToSend[1] = (DWORD)waveMemPtr;
    WriteFile(
        hPipe,
        dataToSend, // the data from the pipe will be put here
        sizeof(dataToSend), // number of bytes allocated
        &written, // this will store number of bytes actually read
        NULL // not using overlapped IO
    );
}

BOOL CopyAudioData(size_t szData) {
	if(!initialized) {
        return FALSE;
	}

	if(szData > szDataAllocated) {
		if(CreateShared(TEXT("AudioSes.Hook.Data"), szData, &hDataMem, &dataMemPtr) != 0) {
            return FALSE;
		}
        szDataAllocated = szData;
	}

    CopyMemory(dataMemPtr, *dataPtrPtr, szData);

    DWORD dataToSend[3], written;
    dataToSend[0] = 0x2;
    dataToSend[1] = (DWORD)waveMemPtr;
    dataToSend[2] = szData;
    WriteFile(
        hPipe,
        dataToSend, // the data from the pipe will be put here
        sizeof(dataToSend), // number of bytes allocated
        &written, // this will store number of bytes actually read
        NULL // not using overlapped IO
    );
	
    return TRUE;
}

BOOL Initialize() {
	if(initialized) {
        return TRUE;
	}

    DWORD hr = CreateShared(TEXT("Local\\AudioSes_Hook_WaveFormat"), sizeof(WAVEFORMATEX), &hWaveMem, &waveMemPtr);
    if(hr != 0) {
        return FALSE;
    }

    hDataMem = NULL;

	hPipe = CreateFile(
        TEXT("\\\\.\\pipe\\audioses.hook"),
        GENERIC_WRITE, // only need read access
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

	if(hPipe == INVALID_HANDLE_VALUE) {
        return GetLastError() != 0;
	}
	
    return initialized = TRUE;
}

HRESULT __cdecl HookedGetBuffer() {
    UINT32 NumFramesRequested;
    BYTE** ppData;
    __asm {
    	push ecx
    	push edx
        mov ecx, dword ptr[ebp + 0xC]
        mov NumFramesRequested, ecx
        mov edx, DWORD PTR [ebp + 0x10]
        mov ppData, edx
    }

    if (!initialized && !Initialize())
        goto func_exit;
	
    ++getBufferFrame;
    dataPtrPtr = ppData;

    func_exit:
	__asm {
        pop edx
		pop ecx
        mov esp, ebp
        pop ebp
        jmp OriginalGetBuffer
	}
}

HRESULT __cdecl HookedReleaseBuffer() {
    UINT32 NumFramesWritten;
    DWORD dwFlags;
    __asm {
        push ecx
        push edx
        mov ecx, dword ptr[ebp + 0xC]
        mov NumFramesWritten, ecx
        mov edx, DWORD PTR[ebp + 0x10]
        mov dwFlags, edx
    }

    if (!initialized)
        goto func_exit;
	
	if(++releaseBufferFrame != getBufferFrame) {
        return E_INVALIDARG;
	}

	if(waveformatPtr != nullptr) {
        auto numBytesWritten = NumFramesWritten * waveformatPtr->nBlockAlign;
        CopyAudioData(numBytesWritten);
        for (size_t i = 0; i < numBytesWritten; i++) {
            *(*dataPtrPtr + i) = 0x00;
        }
	}

	func_exit:
    __asm {
        mov ecx, NumFramesWritten
        mov DWORD PTR[ebp + 0xC], ecx
        mov edx, dwFlags
        mov DWORD PTR[ebp + 0x10], edx
    	
        pop ecx
    	pop edx

        mov esp, ebp
        pop ebp
        jmp OriginalReleaseBuffer
    }
}

void __cdecl HookedPostGetBuffer() {
	__asm {
        push ecx
		push edx
		push esi
		push edi
	}
	if(dataPtrPtr != nullptr)
		dataPtr = *dataPtrPtr;
	
    __asm {
    	pop edi
    	pop esi
    	pop edx
    	pop ecx
        mov esp, ebp
        pop ebp
        jmp OriginalPostGetBuffer
    }
}

HRESULT __cdecl HookedStart() {
    IAudioClient* audioPtr;
    __asm {
        push ecx
        push edx
        mov ecx, dword ptr[ebp + 0x8]
        mov audioPtr, ecx
    }

    audioClientPtr = audioPtr;
	
    if (audioClientPtr != nullptr) {
        WAVEFORMATEX *oldFormat = waveformatPtr;
        OriginalGetMixFormat(audioClientPtr, &waveformatPtr);

    	if(oldFormat == nullptr || memcmp(oldFormat, waveformatPtr, sizeof(WAVEFORMATEX)) != 0) {
            OnWaveFormatChanged();
    	}
    }

    __asm {
        pop edx
        pop ecx
        mov esp, ebp
        pop ebp
        jmp OriginalStart
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	if(ul_reason_for_call != DLL_PROCESS_ATTACH) {
        return TRUE;
	}

    HMODULE audioSesModule = GetModuleHandle(L"AUDIOSES");
    if (audioSesModule == nullptr) {
        return FALSE;
    }
    uintptr_t getBufferPtr = (uintptr_t)audioSesModule + 0x32990 + 0x01000;
    uintptr_t postGetBufferPtr = (uintptr_t)audioSesModule + 0x32B52 + 0x01000;
    uintptr_t releaseBufferPtr = (uintptr_t)audioSesModule + 0x33410 + 0x01000;
    uintptr_t startPtr = (uintptr_t)audioSesModule + 0x36530;

    OriginalGetMixFormat = reinterpret_cast<PFGetMixFormat>((uintptr_t)audioSesModule + 0x7F3F0);
	
    getBufferFrame = 0;
    releaseBufferFrame = 0;
	
    OriginalGetBuffer = (PFGetBuffer)HookFunction(getBufferPtr, (uintptr_t)HookedGetBuffer, 5);
    OriginalReleaseBuffer = (PFReleaseBuffer)HookFunction(releaseBufferPtr, (uintptr_t)HookedReleaseBuffer, 5);
    OriginalPostGetBuffer = (PFPostGetBuffer)HookFunction(postGetBufferPtr, (uintptr_t)HookedPostGetBuffer, 6);
    OriginalStart = (PFStart)HookFunction(startPtr, (uintptr_t)HookedStart, 5);
	
    return TRUE;
}

