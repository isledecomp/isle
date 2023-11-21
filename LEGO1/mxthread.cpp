
#include "mxthread.h"

#include "mxomni.h"
#include "mxtimer.h"

#include <process.h>

// OFFSET: LEGO1 0x100b8bb0
MxTickleThread::MxTickleThread(MxCore* p_target, int p_frequencyMS)
{
	m_target = p_target;
	m_frequencyMS = p_frequencyMS;
}

// Match except for register allocation
// OFFSET: LEGO1 0x100b8c90
MxResult MxTickleThread::Run()
{
	MxTimer* timer = Timer();
	int lastTickled = -m_frequencyMS;
	while (IsRunning()) {
		int currentTime = timer->GetTime();

		if (currentTime < lastTickled) {
			lastTickled = -m_frequencyMS;
		}
		int timeRemainingMS = (m_frequencyMS - currentTime) + lastTickled;
		if (timeRemainingMS <= 0) {
			m_target->Tickle();
			timeRemainingMS = 0;
			lastTickled = currentTime;
		}
		Sleep(timeRemainingMS);
	}
	return MxThread::Run();
}

// OFFSET: LEGO1 0x100bf510
MxThread::MxThread()
{
	m_hThread = NULL;
	m_running = TRUE;
	m_threadId = 0;
}

// OFFSET: LEGO1 0x100bf5a0
MxThread::~MxThread()
{
	if (m_hThread)
		CloseHandle((HANDLE) m_hThread);
}

typedef unsigned(__stdcall* ThreadFunc)(void*);

// OFFSET: LEGO1 0x100bf610
MxResult MxThread::Start(int p_stack, int p_flag)
{
	MxResult result = FAILURE;
	if (m_semaphore.Init(0, 1) == SUCCESS) {
		if (m_hThread =
				_beginthreadex(NULL, p_stack << 2, (ThreadFunc) &MxThread::ThreadProc, this, p_flag, &m_threadId))
			result = SUCCESS;
	}
	return result;
}

// OFFSET: LEGO1 0x100bf660
void MxThread::Sleep(MxS32 p_milliseconds)
{
	::Sleep(p_milliseconds);
}

// OFFSET: LEGO1 0x100bf670
void MxThread::Terminate()
{
	m_running = FALSE;
	m_semaphore.Wait(INFINITE);
}

// OFFSET: LEGO1 0x100bf680
unsigned MxThread::ThreadProc(void* p_thread)
{
	return static_cast<MxThread*>(p_thread)->Run();
}

// OFFSET: LEGO1 0x100bf690
MxResult MxThread::Run()
{
	m_semaphore.Release(1);
	return SUCCESS;
}
