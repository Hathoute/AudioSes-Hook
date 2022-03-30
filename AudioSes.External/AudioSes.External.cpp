// AudioSes.External.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
using namespace std;

BOOL GetWaveFormat(WAVEFORMATEX *pWaveFormat) {
    HANDLE hMapFile = OpenFileMapping(
        FILE_MAP_READ,   // read/write access
        FALSE,                 // do not inherit the name
        L"Local\\AudioSes_Hook_WaveFormat");               // name of mapping object

    if (hMapFile == NULL)
    {
        wcout << "Could not open file mapping object: " << GetLastError() << endl;
        return FALSE;
    }

    WAVEFORMATEX* shared = (WAVEFORMATEX*)MapViewOfFile(hMapFile, // handle to map object
        FILE_MAP_READ,  // read/write permission
        0,
        0,
        sizeof(WAVEFORMATEX));

    if (shared == NULL)
    {
        wcout << "Could not map view of file: " << GetLastError() << endl;
        CloseHandle(hMapFile);
        return FALSE;
    }

    CopyMemory(pWaveFormat, shared, sizeof(WAVEFORMATEX));
    UnmapViewOfFile(shared);
    CloseHandle(hMapFile);
    return TRUE;
}

int main()
{
	
    wcout << "Creating an instance of a named pipe..." << endl;

    // Create a pipe to send data
    HANDLE pipe = CreateNamedPipe(
        L"\\\\.\\pipe\\audioses.hook", // name of the pipe
        PIPE_ACCESS_INBOUND, // 1-way pipe -- send only
        PIPE_TYPE_BYTE, // send data as a byte stream
        1, // only allow 1 instance of this pipe
        0, // no outbound buffer
        0, // no inbound buffer
        0, // use default wait time
        NULL // use default security attributes
    );

    if (pipe == NULL || pipe == INVALID_HANDLE_VALUE) {
        wcout << "Failed to create outbound pipe instance.";
        // look up error code here using GetLastError()
        system("pause");
        return 1;
    }

    wcout << "Waiting for a client to connect to the pipe..." << endl;

    // This call blocks until a client process connects to the pipe
    BOOL result = ConnectNamedPipe(pipe, NULL);
    if (!result) {
        wcout << "Failed to make connection on named pipe." << endl;
        // look up error code here using GetLastError()
        CloseHandle(pipe); // close the pipe
        system("pause");
        return 1;
    }

    wcout << "Receiving data from pipe..." << endl;

	while(true) {
        // This call blocks until a client process reads all the data
        const wchar_t* data = L"*** Hello Pipe World ***";
        DWORD numBytesRead = 0;
        DWORD buffer[1024];
        result = ReadFile(
            pipe,
            buffer, // the data from the pipe will be put here
            sizeof(buffer), // number of bytes allocated
            &numBytesRead, // this will store number of bytes actually read
            NULL // not using overlapped IO
        );

        if(!result) {
            wcout << "Failed to receive data: " << GetLastError() << endl;
            continue;
        }

        DWORD bufCursor = 0;
        DWORD szMessages = numBytesRead / sizeof(DWORD);
        wcout << "Number of bytes read: " << numBytesRead << endl;
        wcout << "Number of DWORDs read: " << szMessages << endl;
		
		while(bufCursor < szMessages) {
            DWORD opCode = buffer[bufCursor++];
            wcout << "Read opcode: " << opCode << endl;
			switch(opCode) {
            case 0x1:
                WAVEFORMATEX format;
                GetWaveFormat(&format);
                wcout << "WAVEFORMATEX pointer address: " << buffer[bufCursor++] << ", format->bps: " << format.wBitsPerSample << endl;
                break;
            case 0x2:
                wcout << "Data pointer: " << buffer[bufCursor++] << ", Data length: " << buffer[bufCursor++] << endl;
                break;
			}
		}
	}

    // Close the pipe (automatically disconnects client too)
    CloseHandle(pipe);

    wcout << "Done." << endl;

    system("pause");
    return 0;
}
