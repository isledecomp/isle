#include "legoomni.h"

#include "mxbackgroundaudiomanager.h"
#include "mxdsfile.h"
#include "legogamestate.h"
#include "legoutil.h"
#include "legoobjectfactory.h"

// 0x100f4588
MxAtomId *g_nocdSourceName = NULL;

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

// OFFSET: LEGO1 0x100b6ff0
void MakeSourceName(char *p_output, const char *p_input)
{
  const char *cln = strchr(p_input, ':');
  if (cln) {
    p_input = cln + 1;
  }

  strcpy(p_output, p_input);

  strlwr(p_output);

  char *extLoc = strstr(p_output, ".si");
  if (extLoc) {
    *extLoc = 0;
  }
}

// OFFSET: LEGO1 0x100b7050
MxBool KeyValueStringParse(char *p_outputValue, const char *p_key, const char *p_source)
{
  MxBool didMatch = FALSE;

  MxS16 len = strlen(p_source);
  char *temp = new char[len + 1];
  strcpy(temp, p_source);

  char *token = strtok(temp, ", \t\r\n:");
  while (token) {
    len -= (strlen(token) + 1);

    if (strcmpi(token, p_key) == 0) {
      if (p_outputValue && len > 0) {
        char *cur = &token[strlen(p_key)];
        cur++;
        while (*cur != ',') {
          if (*cur == ' ' || *cur == '\0' || *cur == '\t' || *cur == '\n' || *cur == '\r')
            break;
          *p_outputValue++ = *cur++;
        }
        *p_outputValue = '\0';
      }

      didMatch = TRUE;
      break;
    }

    token = strtok(NULL, ", \t\r\n:");
  }

  delete[] temp;
  return didMatch;
}

// OFFSET: LEGO1 0x100b7210
void SetOmniUserMessage(void (*p_userMsg)(const char *,int))
{
  g_omniUserMessage = p_userMsg;
}

// OFFSET: LEGO1 0x100acf50
MxResult Start(MxDSAction* p_dsAction)
{
  return MxOmni::GetInstance()->Start(p_dsAction);
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

// OFFSET: LEGO1 0x100c0280
MxDSObject *CreateStreamObject(MxDSFile *p_file, MxS16 p_ofs)
{
  char *buf;
  _MMCKINFO tmp_chunk;

  if (p_file->Seek(((MxLong*)p_file->GetBuffer())[p_ofs], 0)) {
    return NULL;
  }

  if (p_file->Read((MxU8*)&tmp_chunk.ckid, 8) == 0 && tmp_chunk.ckid == FOURCC('M', 'x', 'S', 't')) {
    if (p_file->Read((MxU8*)&tmp_chunk.ckid, 8) == 0 && tmp_chunk.ckid == FOURCC('M', 'x', 'O', 'b')) {

      buf = new char[tmp_chunk.cksize];
      if (!buf) {
        return NULL;
      }

      if (p_file->Read((MxU8*)buf, tmp_chunk.cksize) != 0) {
        return NULL;
      }

      // Save a copy so we can clean up properly, because
      // this function will alter the pointer value.
      char *copy = buf;
      MxDSObject *obj = DeserializeDSObjectDispatch(&buf, -1);
      delete[] copy;
      return obj;
    }
    return NULL;
  }

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
  return g_nocdSourceName->GetInternal();
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
  MxOmni::Init();
  m_unk68 = 0;
  m_inputMgr = NULL;
  m_unk6c = 0;
  m_unk74 = 0;
  m_unk78 = 0;
  m_currentWorld = NULL;
  m_unk80 = FALSE;
  m_isle = NULL;
  m_unk8c = 0;
  m_plantManager = NULL;
  m_gameState = NULL;
  m_animationManager = NULL;
  m_buildingManager = NULL;
  m_bkgAudioManager = NULL;
  m_unk13c = TRUE;
  m_transitionManager = NULL;
}

// OFFSET: LEGO1 0x10058e70 STUB
MxResult LegoOmni::Create(COMPAT_CONST MxOmniCreateParam &p)
{
  MxOmni::Create(p);

  m_objectFactory = new LegoObjectFactory();
  m_gameState = new LegoGameState();
  m_bkgAudioManager = new MxBackgroundAudioManager();

  return SUCCESS;
}

// OFFSET: LEGO1 0x10058c30 STUB
void LegoOmni::Destroy()
{
  // FIXME: Stub
}

// OFFSET: LEGO1 0x1005b580
MxResult LegoOmni::Start(MxDSAction* action)
{
  MxResult result = MxOmni::Start(action);
  this->m_action.SetAtomId(action->GetAtomId());
  this->m_action.SetObjectId(action->GetObjectId());
  this->m_action.SetUnknown24(action->GetUnknown24());
  return result;
}

void LegoOmni::DeleteObject(MxDSAction &ds)
{
  // FIXME: Stub
}

MxBool LegoOmni::DoesEntityExist(MxDSAction &ds)
{
  // FIXME: Stub
  return TRUE;
}

void LegoOmni::vtable0x2c()
{
  // FIXME: Stub
}

int LegoOmni::vtable0x30(char*, int, MxCore*)
{
  // FIXME: Stub
  return 0;
}

void LegoOmni::NotifyCurrentEntity()
{
  // FIXME: Stub
}

// OFFSET: LEGO1 0x1005b640
void LegoOmni::StartTimer()
{
  MxOmni::StartTimer();
  SetAppCursor(2);
}

// OFFSET: LEGO1 0x1005b650
void LegoOmni::StopTimer()
{
  MxOmni::StopTimer();
  SetAppCursor(0);
}

// OFFSET: LEGO1 0x100157a0
LegoWorld *GetCurrentWorld()
{
  return LegoOmni::GetInstance()->GetCurrentWorld();
}
