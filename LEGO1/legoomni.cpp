#include "legoomni.h"
#include "legoobjectfactory.h"

// 0x100f4588
char *g_nocdSourceName = NULL;

// 0x101020e8
void (*g_omniUserMessage)(const char *,int);

// OFFSET: LEGO1 0x10058a00
LegoOmni::LegoOmni()
{
  Init();
}

// OFFSET: LEGO1 0x10058b50
LegoOmni::~LegoOmni()
{
  Destroy();
}

// OFFSET: LEGO1 0x1005b560 STUB
void LegoOmni::CreateBackgroundAudio()
{
  // TODO
}

// OFFSET: LEGO1 0x1005af10 STUB
void LegoOmni::RemoveWorld(const MxAtomId &p1, MxLong p2)
{
  // TODO
}

// OFFSET: LEGO1 0x1005b400 STUB
int LegoOmni::GetCurrPathInfo(LegoPathBoundary **,int &)
{
  // TODO
  return 0;
}

// OFFSET: LEGO1 0x100b6ff0 STUB
void MakeSourceName(char *, const char *)
{
  // TODO
}

// OFFSET: LEGO1 0x100b7210
void SetOmniUserMessage(void (*p_userMsg)(const char *,int))
{
  g_omniUserMessage = p_userMsg;
}

// OFFSET: LEGO1 0x100acf50 STUB
MxLong Start(MxDSAction *)
{
  // TODO
  return 0;
}

// OFFSET: LEGO1 0x1005ad10
LegoOmni *LegoOmni::GetInstance()
{
  return (LegoOmni *)MxOmni::GetInstance();
}

// OFFSET: LEGO1 0x1005ac90
void LegoOmni::CreateInstance()
{
  MxOmni::DestroyInstance();
  MxOmni::SetInstance(new LegoOmni());
}

// OFFSET: LEGO1 0x10015700
LegoOmni *Lego()
{
  return (LegoOmni *)MxOmni::GetInstance();
}

// OFFSET: LEGO1 0x10015710
LegoSoundManager *SoundManager()
{
  return LegoOmni::GetInstance()->GetSoundManager();
}

// OFFSET: LEGO1 0x10015720
LegoVideoManager *VideoManager()
{
  return LegoOmni::GetInstance()->GetVideoManager();
}

// OFFSET: LEGO1 0x100157f0
LegoBuildingManager *BuildingManager()
{
  return LegoOmni::GetInstance()->GetLegoBuildingManager();
}

// OFFSET: LEGO1 0x10015790
Isle *GetIsle()
{
  return LegoOmni::GetInstance()->GetIsle();
}

// OFFSET: LEGO1 0x100157e0
LegoPlantManager *PlantManager()
{
  return LegoOmni::GetInstance()->GetLegoPlantManager();
}

// OFFSET: LEGO1 0x10015730
MxBackgroundAudioManager *BackgroundAudioManager()
{
  return LegoOmni::GetInstance()->GetBackgroundAudioManager();
}

// OFFSET: LEGO1 0x100c0280 STUB
MxDSObject *CreateStreamObject(MxDSFile *,MxS16)
{
  // TODO
  return NULL;
}

// OFFSET: LEGO1 0x10015740
LegoInputManager *InputManager()
{
  return LegoOmni::GetInstance()->GetInputManager();
}

// OFFSET: LEGO1 0x10015760
LegoGameState *GameState()
{
  return LegoOmni::GetInstance()->GetGameState();
}

// OFFSET: LEGO1 0x10015780
LegoNavController *NavController()
{
  return LegoOmni::GetInstance()->GetNavController();
}

// OFFSET: LEGO1 0x10015900
MxTransitionManager *TransitionManager()
{
  return LegoOmni::GetInstance()->GetTransitionManager();
}

// OFFSET: LEGO1 0x10053430
const char *GetNoCD_SourceName()
{
  return g_nocdSourceName;
}

// OFFSET: LEGO1 0x1005b5f0
MxLong LegoOmni::Notify(MxParam &p)
{
  // FIXME: Stub
  return 0;
}

// OFFSET: LEGO1 0x1003dd70 STUB
LegoROI *PickROI(MxLong,MxLong)
{
  // TODO
  return NULL;
}

// OFFSET: LEGO1 0x1003ddc0 STUB
LegoEntity *PickEntity(MxLong,MxLong)
{
  // TODO
  return NULL;
}

// OFFSET: LEGO1 0x10058bd0
void LegoOmni::Init()
{
  // FIXME: Stub
}

// OFFSET: LEGO1 0x10058e70 STUB
MxResult LegoOmni::Create(COMPAT_CONST MxOmniCreateParam &p)
{
  MxOmni::Create(p);

  m_objectFactory = new LegoObjectFactory();
  m_gameState = new LegoGameState();
  return SUCCESS;
}

void LegoOmni::Destroy()
{
  // FIXME: Stub
}

void LegoOmni::vtable20()
{
  // FIXME: Stub
}

void LegoOmni::vtable24(MxDSAction &ds)
{
  // FIXME: Stub
}

MxBool LegoOmni::vtable28(MxDSAction &ds)
{
  // FIXME: Stub
  return TRUE;
}

void LegoOmni::vtable2c()
{
  // FIXME: Stub
}

void LegoOmni::vtable30()
{
  // FIXME: Stub
}

void LegoOmni::vtable34()
{
  // FIXME: Stub
}

void LegoOmni::vtable38()
{
  // FIXME: Stub
}

void LegoOmni::vtable3c()
{
  // FIXME: Stub
}

unsigned char LegoOmni::vtable40()
{
  // FIXME: Stub
  return 0;
}
