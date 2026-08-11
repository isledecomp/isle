#include "mxthread.h"

#include "decomp.h"
#include "mxscheduler.h"

#include <process.h>

DECOMP_SIZE_ASSERT(MxThread, 0x1c)

// MxScheduler's two stubs open THIS translation unit rather than one of their
// own. Retail emits them at 0x100bf4f0 and 0x100bf500 with MxThread::MxThread
// immediately after at 0x100bf510, and BETA10 has StartMultiTasking's `ret 4`
// ending at 0x1014753f with MxThread::MxThread beginning at 0x10147540 -- zero
// bytes of padding between them. Split out, they had no first-level referrer
// (retail contains no call to either) so LINK could satisfy the .def exports
// only in a trailing pass, which put mxscheduler.cpp.obj at the very end of the
// image instead of here, 34 module positions late.

// FUNCTION: LEGO1 0x100bf4f0
MxScheduler* MxScheduler::GetInstance()
{
	// Intentionally empty
	return 0;
}

// FUNCTION: LEGO1 0x100bf500
void MxScheduler::StartMultiTasking(MxULong)
{
	// Intentionally empty
}

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
