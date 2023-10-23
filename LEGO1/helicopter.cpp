#include "helicopter.h"
#include "act3.h"
#include "legoomni.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoworld.h"

// OFFSET: LEGO1 0x10001e60
Helicopter::Helicopter()
{
  m_unk13c = 60;
}

// OFFSET: LEGO1 0x10003230
Helicopter::~Helicopter()
{
  ControlManager()->Unregister(this);
  IslePathActor::Destroy(TRUE);
}

// OFFSET: LEGO1 0x100032c0
MxResult Helicopter::InitFromMxDSObject(MxDSObject &p_dsObject)
{
  MxResult result = IslePathActor::InitFromMxDSObject(p_dsObject);
  LegoWorld *world = GetCurrentWorld();
  SetWorld(world);
  if (world->IsA("Act3")) {
    ((Act3 *)GetWorld())->SetUnkown420c(this);
  }
  world = GetWorld();
  if (world) world->VTable0x58(this); 
  GetState();
  return result;
}

// OFFSET: LEGO1 0x10003320
void Helicopter::GetState()
{
  m_state = (HelicopterState *)GameState()->GetState("HelicopterState");
  if (!m_state) m_state = (HelicopterState *)GameState()->CreateState("HelicopterState");
}