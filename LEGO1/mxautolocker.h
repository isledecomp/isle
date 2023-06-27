#ifndef MXAUTOLOCKER_H
#define MXAUTOLOCKER_H

#include "mxcriticalsection.h"

class MxAutoLocker
{
  public:
    MxAutoLocker(MxCriticalSection* cs);
    ~MxAutoLocker();
  private:
    MxCriticalSection* m_criticalSection;
};

#endif // MXAUTOLOCKER_H
