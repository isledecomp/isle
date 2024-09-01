#ifndef MXTIMER_H
#define MXTIMER_H

#include "mxcore.h"

// VTABLE: LEGO1 0x100dc0e0
// VTABLE: BETA10 0x101c1bb0
// SIZE 0x10
class MxTimer : public MxCore {
public:
	MxTimer();

	void Start();
	void Stop();

	MxLong GetRealTime();

	// FUNCTION: BETA10 0x1012bf50
	void InitLastTimeCalculated() { g_lastTimeCalculated = m_startTime; }

	// FUNCTION: BETA10 0x10017810
	MxLong GetTime()
	{
		// Note that the BETA10 implementation differs - it only consists of the second branch of this `if` call
		if (m_isRunning) {
			return g_lastTimeTimerStarted;
		}
		else {
			return g_lastTimeCalculated - m_startTime;
		}
	}

	// SYNTHETIC: LEGO1 0x100ae0d0
	// SYNTHETIC: BETA10 0x1012bf80
	// MxTimer::`scalar deleting destructor'

private:
	MxLong m_startTime; // 0x08
	MxBool m_isRunning; // 0x0c

	static MxLong g_lastTimeCalculated;
	static MxLong g_lastTimeTimerStarted;
};

// SYNTHETIC: BETA10 0x1012bfc0
// MxTimer::~MxTimer

#endif // MXTIMER_H
