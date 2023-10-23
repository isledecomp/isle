#include "legoanimationmanager.h"

// 0x100f74f8
int g_legoAnimationManagerConfig = 1;

// OFFSET: LEGO1 0x1005eb60 STUB
LegoAnimationManager::LegoAnimationManager()
{
}

// OFFSET: LEGO1 0x1005ed30 STUB
LegoAnimationManager::~LegoAnimationManager()
{
  // TODO
}

// OFFSET: LEGO1 0x100619f0 STUB
MxLong LegoAnimationManager::Notify(MxParam &p)
{
  // TODO

  return 0;
}

// OFFSET: LEGO1 0x10061cc0 STUB
MxResult LegoAnimationManager::Tickle()
{
  // TODO

  return SUCCESS;
}

// OFFSET: LEGO1 0x1005f130 STUB
void LegoAnimationManager::Init()
{
  // TODO
}

// OFFSET: LEGO1 0x1005eb50
void LegoAnimationManager::configureLegoAnimationManager(int param_1)
{
  g_legoAnimationManagerConfig = param_1;
}
