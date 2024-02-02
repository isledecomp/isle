#ifndef MXTIMER_H
#define MXTIMER_H

#include "mxcore.h"

// VTABLE: LEGO1 0x100dc0e0
// SIZE 0x10
class MxTimer : public MxCore {
public:
	MxTimer();

	void Start();
	void Stop();

	MxLong GetRealTime();

	inline MxLong GetTime()
	{
		if (this->m_isRunning) {
			return g_lastTimeTimerStarted;
		}
		else {
			return g_lastTimeCalculated - this->m_startTime;
		}
	}

	// SYNTHETIC: LEGO1 0x100ae0d0
	// MxTimer::`scalar deleting destructor'

private:
	MxLong m_startTime;
	MxBool m_isRunning;
	static MxLong g_lastTimeCalculated;
	static MxLong g_lastTimeTimerStarted;
};

#endif // MXTIMER_H
