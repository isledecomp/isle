#ifndef MXTHREAD_H
#define MXTHREAD_H

#include "compat.h"
#include "mxsemaphore.h"
#include "mxtypes.h"

class MxCore;

// VTABLE: LEGO1 0x100dc860
class MxThread {
public:
	// Note: Comes before virtual destructor
	virtual MxResult Run();

	MxResult Start(MxS32 p_stack, MxS32 p_flag);

	void Terminate();

	static void Sleep(MxS32 p_milliseconds);

	// Inferred, not in DLL
	inline MxBool IsRunning() { return m_running; }

protected:
	MxThread();

public:
	virtual ~MxThread();

private:
	static unsigned ThreadProc(void* p_thread);

	MxULong m_hThread;
	MxU32 m_threadId;
	MxBool m_running;
	MxSemaphore m_semaphore;

protected:
	MxCore* m_target;
};

// VTABLE: LEGO1 0x100dc6d8
class MxTickleThread : public MxThread {
public:
	MxTickleThread(MxCore* p_target, MxS32 p_frequencyMS);

	// Only inlined, no offset
	virtual ~MxTickleThread() {}

	MxResult Run() override;

private:
	MxS32 m_frequencyMS;
};

#endif // MXTHREAD_H
