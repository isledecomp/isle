#ifndef MXCRITICALSECTION_H
#define MXCRITICALSECTION_H

#include <windows.h>

// SIZE 0x1c
class MxCriticalSection {
public:
	__declspec(dllexport) MxCriticalSection();
	__declspec(dllexport) ~MxCriticalSection();
	__declspec(dllexport) static void SetDoMutex();
	void Enter();
	void Leave();

private:
	CRITICAL_SECTION m_criticalSection; // 0x00
	HANDLE m_mutex;                     // 0x18
};

#endif // MXCRITICALSECTION_H
