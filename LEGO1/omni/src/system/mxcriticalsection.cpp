#include "mxcriticalsection.h"

#include "decomp.h"

#include <stdio.h>

DECOMP_SIZE_ASSERT(MxCriticalSection, 0x1c)

// GLOBAL: LEGO1 0x10101e78
BOOL g_useMutex = FALSE;

// FUNCTION: LEGO1 0x100b6d20
MxCriticalSection::MxCriticalSection()
{
	HANDLE mutex;

	if (g_useMutex) {
		mutex = CreateMutex(NULL, FALSE, NULL);
		m_mutex = mutex;
	}
	else {
		InitializeCriticalSection(&m_criticalSection);
		m_mutex = NULL;
	}
}

// FUNCTION: LEGO1 0x100b6d60
MxCriticalSection::~MxCriticalSection()
{
	if (m_mutex != NULL) {
		CloseHandle(m_mutex);
	}
	else {
		DeleteCriticalSection(&m_criticalSection);
	}
}

// FUNCTION: LEGO1 0x100b6d80
// FUNCTION: BETA10 0x1013c725
void MxCriticalSection::Enter()
{
	DWORD result;
	FILE* file;

	if (m_mutex != NULL) {
		result = WaitForSingleObject(m_mutex, 5000);
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
		EnterCriticalSection(&m_criticalSection);
	}
}

// FUNCTION: LEGO1 0x100b6de0
void MxCriticalSection::Leave()
{
	if (m_mutex != NULL) {
		ReleaseMutex(m_mutex);
	}
	else {
		LeaveCriticalSection(&m_criticalSection);
	}
}

// FUNCTION: LEGO1 0x100b6e00
void MxCriticalSection::SetDoMutex()
{
	g_useMutex = TRUE;
}
