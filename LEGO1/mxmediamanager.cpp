#include "mxmediamanager.h"
#include "mxautolocker.h"
#include "decomp.h"

DECOMP_SIZE_ASSERT(MxMediaManager, 0x2c);

// OFFSET: LEGO1 0x100b84c0
MxMediaManager::MxMediaManager()
{
  Init();
}

// OFFSET: LEGO1 0x100b8560
MxMediaManager::~MxMediaManager()
{
  Destroy();
}

// OFFSET: LEGO1 0x100b85d0
MxResult MxMediaManager::Init()
{
  this->m_presenters = NULL;
  this->m_thread = NULL;
  return SUCCESS;
}

// OFFSET: LEGO1 0x100b8790 STUB
MxResult MxMediaManager::Tickle()
{
  return SUCCESS;
}

// OFFSET: LEGO1 0x100b85e0
MxResult MxMediaManager::InitPresenters()
{
  MxAutoLocker lock(&this->m_criticalSection);

  this->m_presenters = new MxPresenterList;

  if (!this->m_presenters) {
    this->Destroy();
    return FAILURE;
  }

  return SUCCESS;
}

// OFFSET: LEGO1 0x100b8710
void MxMediaManager::Destroy()
{
  MxAutoLocker lock(&this->m_criticalSection);

  if (this->m_presenters)
    delete this->m_presenters;
    
  Init();
}

// OFFSET: LEGO1 0x100b88c0
void MxMediaManager::AddPresenter(MxPresenter &p_presenter)
{
  MxAutoLocker lock(&this->m_criticalSection);

  this->m_presenters->Append(&p_presenter);
}

// OFFSET: LEGO1 0x100b8980 STUB
void MxMediaManager::RemovePresenter(MxPresenter &p_presenter)
{
  MxAutoLocker lock(&this->m_criticalSection);

  // Remove element from m_presenters
}

// OFFSET: LEGO1 0x100b8ac0 STUB
void MxMediaManager::StopPresenters()
{
  MxAutoLocker lock(&this->m_criticalSection);
  
  // Call EndAction on all presenters in list
}
