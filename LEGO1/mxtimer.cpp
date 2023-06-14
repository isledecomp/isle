#include "mxtimer.h"

#include <windows.h>

long MxTimer::s_LastTimeCalculated = 0;
long MxTimer::s_LastTimeTimerStarted = 0;

MxTimer::MxTimer()
{
  this->m_isRunning = FALSE;
  MxTimer::s_LastTimeCalculated = timeGetTime();
  this->m_startTime = MxTimer::s_LastTimeCalculated;
}

void MxTimer::Start()
{
  this->m_isRunning = TRUE;
  MxTimer::s_LastTimeTimerStarted = timeGetTime();
}

void MxTimer::Stop()
{
  long elapsed = this->GetRealTime();
  long startTime = elapsed - MxTimer::s_LastTimeTimerStarted;
  this->m_isRunning = FALSE;
  // this feels very stupid but it's what the assembly does
  this->m_startTime = this->m_startTime + startTime - 5;
}

long MxTimer::GetRealTime()
{
  MxTimer::s_LastTimeCalculated = timeGetTime();
  return MxTimer::s_LastTimeCalculated - this->m_startTime;
}
