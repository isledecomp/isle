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

// OFFSET: LEGO1 0x100d13d0 STUB
MxResult MxDiskStreamProvider::SetResourceToGet(void* p_resource)
{
  // TODO
  return FAILURE;
}

// OFFSET: LEGO1 0x100d1e90
MxU32 MxDiskStreamProvider::GetFileSize()
{
  return m_pFile->GetBufferSize();
}

// OFFSET: LEGO1 0x100d1ea0
MxU32 MxDiskStreamProvider::GetStreamBuffersNum()
{
  return m_pFile->GetStreamBuffersNum();
}

// OFFSET: LEGO1 0x100d15e0 STUB
void MxDiskStreamProvider::vtable0x20(undefined4 p_unknown1)
{
  // TODO
}

// OFFSET: LEGO1 0x100d1eb0
MxU32 MxDiskStreamProvider::GetLengthInDWords()
{
  return m_pFile->GetLengthInDWords();
}

// OFFSET: LEGO1 0x100d1ec0
MxU32* MxDiskStreamProvider::GetBufferForDWords()
{
  return m_pFile->GetBuffer();
}
