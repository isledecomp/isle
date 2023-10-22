#include "legoworld.h"
#include "legoomni.h"
#include "legoinputmanager.h"
#include "mxticklemanager.h"

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
void LegoWorld::Stop() {
  TickleManager()->UnregisterClient(this);
}

// OFFSET: LEGO1 0x1001d670
MxBool LegoWorld::VTable0x5c() {
  return FALSE; 
}

// OFFSET: LEGO1 0x100010a0
void LegoWorld::VTable0x60() {
}

// OFFSET: LEGO1 0x10021a70 STUB
void LegoWorld::VTable0x68(MxBool p_add) {
}

// OFFSET: LEGO1 0x1001e0b0 STUB
MxResult LegoWorld::SetAsCurrentWorld(MxDSObject& p_object)
{
  return SUCCESS;
}

// OFFSET: LEGO1 0x10015820 STUB
void FUN_10015820(MxU32 p_1, MxU32 p_2)
{

}

// OFFSET: LEGO1 0x10015910 STUB
void FUN_10015910(MxU32 p_1)
{

}

// OFFSET: LEGO1 0x100159c0
void SetIsWorldActive(MxBool p_active)
{
  if (!p_active) LegoOmni::GetInstance()->GetInputManager()->SetCamera(NULL);
  g_isWorldActive = p_active;
}