#ifndef MXCRITICALSECTION_H
#define MXCRITICALSECTION_H

#include <windows.h>

// SIZE 0x1c
class MxCriticalSection {
public:
	MxCriticalSection();
	~MxCriticalSection();

	static void SetDoMutex();

#ifdef BETA10
	void Enter(unsigned long p_threadId, const char* filename, int line);
#else
	void Enter();
#endif
	void Leave();

private:
	CRITICAL_SECTION m_criticalSection; // 0x00
	HANDLE m_mutex;                     // 0x18
};

#ifdef BETA10
// TODO: Not quite correct yet, the second argument becomes a relocated value
#define ENTER(criticalSection) criticalSection.Enter(-1, NULL, 0)
#else
#define ENTER(criticalSection) criticalSection.Enter()
#endif

#endif // MXCRITICALSECTION_H
