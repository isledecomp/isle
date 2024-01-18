#ifndef MXTHREAD_H
#define MXTHREAD_H

#include "compat.h"
#include "mxsemaphore.h"
#include "mxtypes.h"

class MxCore;

// VTABLE: LEGO1 0x100dc860
// SIZE 0x1c
class MxThread {
public:
	// Note: Comes before virtual destructor
	virtual MxResult Run();

	MxResult Start(MxS32 p_stack, MxS32 p_flag);

	void Terminate();
	void Sleep(MxS32 p_milliseconds);

	inline MxBool IsRunning() { return m_running; }

	// SYNTHETIC: LEGO1 0x100bf580
	// MxThread::`scalar deleting destructor'

protected:
	MxThread();

public:
	virtual ~MxThread();

private:
	static unsigned ThreadProc(void* p_thread);

	MxULong m_hThread;       // 0x04
	MxU32 m_threadId;        // 0x08
	MxBool m_running;        // 0x0c
	MxSemaphore m_semaphore; // 0x10

protected:
	MxCore* m_target; // 0x18
};

// VTABLE: LEGO1 0x100dc6d8
// SIZE 0x20
class MxTickleThread : public MxThread {
public:
	MxTickleThread(MxCore* p_target, MxS32 p_frequencyMS);
	virtual ~MxTickleThread() {}

	MxResult Run() override;

	// SYNTHETIC: LEGO1 0x100b8c20
	// MxTickleThread::`scalar deleting destructor'

private:
	MxS32 m_frequencyMS; // 0x1c
};

#endif // MXTHREAD_H
