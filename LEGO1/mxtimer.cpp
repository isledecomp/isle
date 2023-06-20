#include "mxtimer.h"

#include "legoinc.h"

// 0x10101414
long MxTimer::s_LastTimeCalculated = 0;

// 0x10101418
long MxTimer::s_LastTimeTimerStarted = 0;

// OFFSET: LEGO1 0x100ae060
MxTimer::MxTimer()
{
  this->m_isRunning = MX_FALSE;
  MxTimer::s_LastTimeCalculated = timeGetTime();
  this->m_startTime = MxTimer::s_LastTimeCalculated;
}

// OFFSET: LEGO1 0x100ae160
void MxTimer::Start()
{
  MxTimer::s_LastTimeTimerStarted = timeGetTime();
  this->m_isRunning = MX_TRUE;
}

// OFFSET: LEGO1 0x100ae180
void MxTimer::Stop()
{
  long elapsed = this->GetRealTime();
  long startTime = elapsed - MxTimer::s_LastTimeTimerStarted;
  this->m_isRunning = MX_FALSE;
  // this feels very stupid but it's what the assembly does
  this->m_startTime = this->m_startTime + startTime - 5;
}

// OFFSET: LEGO1 0x100ae140
long MxTimer::GetRealTime()
{
  MxTimer::s_LastTimeCalculated = timeGetTime();
  return MxTimer::s_LastTimeCalculated - this->m_startTime;
}
