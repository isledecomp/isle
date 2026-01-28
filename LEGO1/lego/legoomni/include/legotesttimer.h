#ifndef LEGOTESTTIMER_H
#define LEGOTESTTIMER_H

#include "decomp.h"
#include "misc/legotypes.h"
#include "mxcore.h"
#include "mxparam.h"

// VTABLE: BETA10 0x101bed08
// SIZE 0x24
class LegoTestTimer : public MxCore {
public:
	LegoTestTimer(LegoS32 p_numTimers, LegoS32 p_interval, LegoS32 p_numBins, LegoS32 p_type);
	~LegoTestTimer() override;                // vtable+00
	MxLong Notify(MxParam& p_param) override; // vtable+04

	// FUNCTION: BETA10 0x100d18e0
	static const char* HandlerClassName() { return "LegoTestTimer"; }

	// FUNCTION: BETA10 0x100d18b0
	const char* ClassName() const override // vtable+0c
	{
		return HandlerClassName();
	}

	void Tick(LegoS32 p_timer);
	void ResetAtNextTick();
	void Print();

	// SYNTHETIC: BETA10 0x100d1900
	// LegoTestTimer::`scalar deleting destructor'

private:
	LegoS32** m_timers;     // 0x08
	LegoS32* m_lastTime;    // 0x0c
	LegoS32* m_totalTime;   // 0x10
	LegoS32 m_numTimers;    // 0x14
	LegoS32 m_numBins;      // 0x18
	LegoS32 m_interval;     // 0x1c
	MxBool m_enable;        // 0x20
	MxBool m_keyRegistered; // 0x21
};

#endif // LEGOTESTTIMER_H
