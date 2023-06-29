#ifndef MXTIMER_H
#define MXTIMER_H

#include "mxcore.h"

// VTABLE 0x100dc0e0
// SIZE 0x10
class MxTimer : public MxCore
{
public:
  MxTimer();

  void Start();
  void Stop();

  __declspec(dllexport) long GetRealTime();

  long GetTime() inline
  {
    if (this->m_isRunning)
      return s_LastTimeCalculated;
    else
      return s_LastTimeCalculated - this->m_startTime;
  }

private:
  long m_startTime;
  MxBool m_isRunning;
  static long s_LastTimeCalculated;
  static long s_LastTimeTimerStarted;
};

#endif // MXTIMER_H
