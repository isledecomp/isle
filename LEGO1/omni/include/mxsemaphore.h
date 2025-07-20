#ifndef MXSEMAPHORE_H
#define MXSEMAPHORE_H

#include "mxtypes.h"

#include <windows.h>

// VTABLE: LEGO1 0x100dccf0
// VTABLE: BETA10 0x101c28ac
// SIZE 0x08
class MxSemaphore {
public:
	MxSemaphore();

	// FUNCTION: LEGO1 0x100c87e0
	// FUNCTION: BETA10 0x101592a9
	~MxSemaphore() { CloseHandle(m_hSemaphore); }

	virtual MxResult Init(MxU32 p_initialCount, MxU32 p_maxCount);

	void Acquire(MxU32 p_timeoutMS);
	void TryAcquire();
	void Release(MxU32 p_releaseCount);

private:
	HANDLE m_hSemaphore; // 0x04
};

#endif // MXSEMAPHORE_H
