#include "mxeventmanager.h"
#include "decomp.h"

// OFFSET: LEGO1 0x100c0360
MxEventManager::MxEventManager()
{
  Init();
}

// OFFSET: LEGO1 0x100c03f0
MxEventManager::~MxEventManager()
{
  // TODO: MxMediaManager::TerminateThread call
}

// OFFSET: LEGO1 0x100c0450
void MxEventManager::Init()
{
}

// OFFSET: LEGO1 0x100c04a0 STUB
MxResult MxEventManager::vtable0x28(undefined4 p_unknown1, MxU8 p_unknown2)
{
  //TODO
  return FAILURE;
}
