#include "mxmediamanager.h"
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
  Teardown();
}

// OFFSET: LEGO1 0x100b85d0
MxResult MxMediaManager::Init()
{
  this->m_unk08 = NULL;
  this->m_thread = NULL;
  return SUCCESS;
}

// OFFSET: LEGO1 0x100b8710
void MxMediaManager::Teardown()
{
  if(this->m_unk08) {
    delete this->m_unk08;
  }
  Init();
}