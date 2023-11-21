#include "mxtimer.h"

#include <windows.h>

// 0x10101414
MxLong MxTimer::s_LastTimeCalculated = 0;

// 0x10101418
MxLong MxTimer::s_LastTimeTimerStarted = 0;

// OFFSET: LEGO1 0x100ae060
MxTimer::MxTimer()
{
	this->m_isRunning = FALSE;
	m_startTime = timeGetTime();
	// yeah this is somehow what the asm is
	s_LastTimeCalculated = m_startTime;
}

// OFFSET: LEGO1 0x100ae140
MxLong MxTimer::GetRealTime()
{
	MxTimer::s_LastTimeCalculated = timeGetTime();
	return MxTimer::s_LastTimeCalculated - this->m_startTime;
}

// OFFSET: LEGO1 0x100ae160
void MxTimer::Start()
{
	s_LastTimeTimerStarted = this->GetRealTime();
	this->m_isRunning = TRUE;
}

// OFFSET: LEGO1 0x100ae180
void MxTimer::Stop()
{
	MxLong elapsed = this->GetRealTime();
	MxLong startTime = elapsed - MxTimer::s_LastTimeTimerStarted;
	this->m_isRunning = FALSE;
	// this feels very stupid but it's what the assembly does
	this->m_startTime = this->m_startTime + startTime - 5;
}
