#include "mxcriticalsection.h"

#include "decomp.h"

#include <stdio.h>

DECOMP_SIZE_ASSERT(MxCriticalSection, 0x1c);

// GLOBAL: LEGO1 0x10101e78
int g_useMutex = 0;

// FUNCTION: LEGO1 0x100b6d20
MxCriticalSection::MxCriticalSection()
{
	HANDLE mutex;

	if (g_useMutex != 0) {
		mutex = CreateMutexA(NULL, FALSE, NULL);
		this->m_mutex = mutex;
		return;
	}

	InitializeCriticalSection(&this->m_criticalSection);
	this->m_mutex = NULL;
}

// FUNCTION: LEGO1 0x100b6d60
MxCriticalSection::~MxCriticalSection()
{
	if (this->m_mutex != NULL) {
		CloseHandle(this->m_mutex);
		return;
	}

	DeleteCriticalSection(&this->m_criticalSection);
}

// FUNCTION: LEGO1 0x100b6d80
void MxCriticalSection::Enter()
{
	DWORD result;
	FILE* file;

	if (this->m_mutex != NULL) {
		result = WaitForSingleObject(this->m_mutex, 5000);
		if (result == WAIT_FAILED) {
			file = fopen("C:\\DEADLOCK.TXT", "a");
			if (file != NULL) {
				fprintf(file, "mutex timeout occurred!\n");
				fclose(file);
			}

			abort();
		}
	}
	else {
		EnterCriticalSection(&this->m_criticalSection);
	}
}

// FUNCTION: LEGO1 0x100b6de0
void MxCriticalSection::Leave()
{
	if (this->m_mutex != NULL) {
		ReleaseMutex(this->m_mutex);
		return;
	}

	LeaveCriticalSection(&this->m_criticalSection);
}

// FUNCTION: LEGO1 0x100b6e00
void MxCriticalSection::SetDoMutex()
{
	g_useMutex = 1;
}
