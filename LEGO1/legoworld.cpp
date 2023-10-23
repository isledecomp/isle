#include "legoworld.h"
#include "legoomni.h"
#include "legoinputmanager.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(LegoWorld, 0xf8);

MxBool g_isWorldActive;

// OFFSET: LEGO1 0x1001ca40 STUB
LegoWorld::LegoWorld()
{
  // TODO
}

// OFFSET: LEGO1 0x1001dfa0 STUB
LegoWorld::~LegoWorld()
{
  // TODO
}

// OFFSET: LEGO1 0x10022340
void LegoWorld::Stop()
{
  TickleManager()->UnregisterClient(this);
}

// OFFSET: LEGO1 0x1001f630 STUB
void LegoWorld::VTable0x54()
{
  // TODO
}

// OFFSET: LEGO1 0x10020220 STUB
void LegoWorld::VTable0x58()
{
  // TODO
}

// OFFSET: LEGO1 0x1001d670
MxBool LegoWorld::VTable0x5c()
{
  return FALSE; 
}

// OFFSET: LEGO1 0x100010a0
void LegoWorld::VTable0x60()
{
}

// OFFSET: LEGO1 0x1001d680
MxBool LegoWorld::VTable0x64()
{
  return FALSE;
}

// OFFSET: LEGO1 0x10021a70 STUB
void LegoWorld::VTable0x68(MxBool p_add) 
{
  // TODO
}

// OFFSET: LEGO1 0x1001e0b0 STUB
MxResult LegoWorld::SetAsCurrentWorld(MxDSObject &p_dsObject)
{
  // TODO
  return SUCCESS;
}

// OFFSET: LEGO1 0x10015820 STUB
void FUN_10015820(MxU32 p_unk1, MxU32 p_unk2)
{
  // TODO
}

// OFFSET: LEGO1 0x10015910 STUB
void FUN_10015910(MxU32 p_unk1)
{
  // TODO
}

// OFFSET: LEGO1 0x100159c0
void SetIsWorldActive(MxBool p_isWorldActive)
{
  if (!p_isWorldActive)
    LegoOmni::GetInstance()->GetInputManager()->SetCamera(NULL);
  g_isWorldActive = p_isWorldActive;
}