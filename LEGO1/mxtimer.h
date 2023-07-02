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

  __declspec(dllexport) MxLong GetRealTime();

  inline MxLong GetTime()
  {
    if (this->m_isRunning)
      return s_LastTimeCalculated;
    else
      return s_LastTimeCalculated - this->m_startTime;
  }

private:
  MxLong m_startTime;
  MxBool m_isRunning;
  static MxLong s_LastTimeCalculated;
  static MxLong s_LastTimeTimerStarted;
};

#endif // MXTIMER_H
