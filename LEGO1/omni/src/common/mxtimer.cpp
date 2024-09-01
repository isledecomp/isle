#include "mxtimer.h"

#include <windows.h>

// GLOBAL: LEGO1 0x10101414
// GLOBAL: BETA10 0x10201f84
MxLong MxTimer::g_lastTimeCalculated = 0;

// GLOBAL: LEGO1 0x10101418
MxLong MxTimer::g_lastTimeTimerStarted = 0;

// FUNCTION: LEGO1 0x100ae060
// FUNCTION: BETA10 0x1012bea0
MxTimer::MxTimer()
{
	m_isRunning = FALSE;
	m_startTime = timeGetTime();
	InitLastTimeCalculated();
}

// FUNCTION: LEGO1 0x100ae140
// FUNCTION: BETA10 0x1012bf23
MxLong MxTimer::GetRealTime()
{
	MxTimer::g_lastTimeCalculated = timeGetTime();
	return MxTimer::g_lastTimeCalculated - m_startTime;
}

// FUNCTION: LEGO1 0x100ae160
void MxTimer::Start()
{
	g_lastTimeTimerStarted = GetRealTime();
	m_isRunning = TRUE;
}

// FUNCTION: LEGO1 0x100ae180
void MxTimer::Stop()
{
	MxLong elapsed = GetRealTime();
	MxLong startTime = elapsed - MxTimer::g_lastTimeTimerStarted;
	m_isRunning = FALSE;
	// this feels very stupid but it's what the assembly does
	m_startTime = m_startTime + startTime - 5;
}
