#include "mxautolocker.h"

// OFFSET: LEGO1 0x100b8ed0
MxAutoLocker::MxAutoLocker(MxCriticalSection *critsect)
{
  this->m_criticalSection = critsect;
  if (this->m_criticalSection != 0)
    this->m_criticalSection->Enter();
}

// OFFSET: LEGO1 0x100b8ef0
MxAutoLocker::~MxAutoLocker()
{
  if (this->m_criticalSection != 0)
    this->m_criticalSection->Leave();
}
