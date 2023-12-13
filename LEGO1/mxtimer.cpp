#include "mxtimer.h"

#include <windows.h>

// GLOBAL: LEGO1 0x10101414
MxLong MxTimer::g_lastTimeCalculated = 0;

// GLOBAL: LEGO1 0x10101418
MxLong MxTimer::g_lastTimeTimerStarted = 0;

// FUNCTION: LEGO1 0x100ae060
MxTimer::MxTimer()
{
	this->m_isRunning = FALSE;
	m_startTime = timeGetTime();
	// yeah this is somehow what the asm is
	g_lastTimeCalculated = m_startTime;
}

// FUNCTION: LEGO1 0x100ae140
MxLong MxTimer::GetRealTime()
{
	MxTimer::g_lastTimeCalculated = timeGetTime();
	return MxTimer::g_lastTimeCalculated - this->m_startTime;
}

// FUNCTION: LEGO1 0x100ae160
void MxTimer::Start()
{
	g_lastTimeTimerStarted = this->GetRealTime();
	this->m_isRunning = TRUE;
}

// FUNCTION: LEGO1 0x100ae180
void MxTimer::Stop()
{
	MxLong elapsed = this->GetRealTime();
	MxLong startTime = elapsed - MxTimer::g_lastTimeTimerStarted;
	this->m_isRunning = FALSE;
	// this feels very stupid but it's what the assembly does
	this->m_startTime = this->m_startTime + startTime - 5;
}
