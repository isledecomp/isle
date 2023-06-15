#include "mxautolocker.h"

MxAutoLocker::MxAutoLocker(MxCriticalSection *critsect)
{
  this->m_criticalSection = critsect;
  if (this->m_criticalSection != 0)
    this->m_criticalSection->Enter();
}

MxAutoLocker::~MxAutoLocker()
{
  if (this->m_criticalSection != 0)
    this->m_criticalSection->Leave();
}
