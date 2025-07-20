#include "mxthread.h"

#include "decomp.h"

#include <process.h>

DECOMP_SIZE_ASSERT(MxThread, 0x1c)

// FUNCTION: LEGO1 0x100bf510
// FUNCTION: BETA10 0x10147540
MxThread::MxThread()
{
	m_hThread = NULL;
	m_threadId = 0;
	m_running = TRUE;
}

// FUNCTION: LEGO1 0x100bf5a0
// FUNCTION: BETA10 0x101475d0
MxThread::~MxThread()
{
	if (m_hThread) {
		CloseHandle((HANDLE) m_hThread);
	}
}

typedef unsigned(__stdcall* ThreadFunc)(void*);

// FUNCTION: LEGO1 0x100bf610
// FUNCTION: BETA10 0x10147655
MxResult MxThread::Start(MxS32 p_stackSize, MxS32 p_flag)
{
	MxResult result = FAILURE;

	if (m_semaphore.Init(0, 1) != SUCCESS) {
		goto done;
	}

	m_hThread = _beginthreadex(NULL, p_stackSize * 4, (ThreadFunc) &MxThread::ThreadProc, this, p_flag, &m_threadId);
	if (!m_hThread) {
		goto done;
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x100bf660
// FUNCTION: BETA10 0x101476ee
void MxThread::Sleep(MxS32 p_milliseconds)
{
	::Sleep(p_milliseconds);
}

// FUNCTION: BETA10 0x10147710
void MxThread::ResumeThread()
{
	::ResumeThread((HANDLE) m_hThread);
}

// FUNCTION: BETA10 0x10147733
void MxThread::SuspendThread()
{
	::SuspendThread((HANDLE) m_hThread);
}

// FUNCTION: BETA10 0x10147756
BOOL MxThread::TerminateThread(MxU32 p_exitCode)
{
	// TerminateThread returns nonzero for success, zero for failure
	return ::TerminateThread((HANDLE) m_hThread, p_exitCode) == 0;
}

// FUNCTION: BETA10 0x10147793
MxS32 MxThread::GetThreadPriority(MxU16& p_priority)
{
	return (p_priority = ::GetThreadPriority((HANDLE) m_hThread));
}

// FUNCTION: BETA10 0x101477c8
BOOL MxThread::SetThreadPriority(MxU16 p_priority)
{
	// SetThreadPriority returns nonzero for success, zero for failure
	return ::SetThreadPriority((HANDLE) m_hThread, p_priority) == 0;
}

// FUNCTION: LEGO1 0x100bf670
// FUNCTION: BETA10 0x1014780a
void MxThread::Terminate()
{
	m_running = FALSE;
	m_semaphore.Acquire(INFINITE);
}

// FUNCTION: LEGO1 0x100bf680
// FUNCTION: BETA10 0x1014783b
unsigned MxThread::ThreadProc(void* p_thread)
{
	return static_cast<MxThread*>(p_thread)->Run();
}

// FUNCTION: LEGO1 0x100bf690
// FUNCTION: BETA10 0x10147855
MxResult MxThread::Run()
{
	m_semaphore.Release(1);
	return SUCCESS;
}
