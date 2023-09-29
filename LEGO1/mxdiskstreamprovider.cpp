#include "mxdiskstreamprovider.h"

#include "mxthread.h"

DECOMP_SIZE_ASSERT(MxDiskStreamProvider, 0x60);

// OFFSET: LEGO1 0x100d0f30
MxResult MxDiskStreamProviderThread::Run()
{
  if (m_target != NULL)
    m_target->WaitForWorkToComplete();
  MxThread::Run();
  // They should probably have writen "return MxThread::Run()" but they didn't.
  return SUCCESS;
}

// OFFSET: LEGO1 0x100d0f70
MxDiskStreamProvider::MxDiskStreamProvider()
{
  this->m_pFile = NULL;
  this->m_remainingWork = 0;
  this->m_unk35 = 0;
}

// OFFSET: LEGO1 0x100d1240
MxDiskStreamProvider::~MxDiskStreamProvider()
{
  // TODO
}

// Matching but with esi / edi swapped
// OFFSET: LEGO1 0x100d1750
MxResult MxDiskStreamProvider::WaitForWorkToComplete()
{
  while (m_remainingWork != 0)
  {
    m_busySemaphore.Wait(INFINITE);
    if (m_unk35 != 0)
      PerformWork();
  }
  return SUCCESS;
}

// OFFSET: LEGO1 0x100d1760 STUB
void MxDiskStreamProvider::PerformWork()
{
  // TODO
}