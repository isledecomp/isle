#include "legoentity.h"

#include "legoomni.h"
#include "legoutil.h"
#include "define.h"

DECOMP_SIZE_ASSERT(LegoEntity, 0x68)

// OFFSET: LEGO1 0x1000c290
LegoEntity::~LegoEntity()
{
  Destroy(TRUE);
}

// OFFSET: LEGO1 0x100114f0 STUB
MxLong LegoEntity::Notify(MxParam &p)
{
  // TODO

  return 0;
}

// OFFSET: LEGO1 0x100105f0
void LegoEntity::Reset()
{
  m_vec1.Fill(0);
  m_vec2.Fill(0);
  m_unk50 = 0;
  m_unk54 = 0;
  m_unk58 = 0;
  m_actionArgString = NULL;
  m_unk10 = 0;
  m_unk11 = 0;
  m_actionType = ExtraActionType_unknown;
  m_actionArgNumber = -1;
  m_unk59 = 4;
}

// OFFSET: LEGO1 0x100107e0
MxResult LegoEntity::InitFromMxDSObject(MxDSObject& p_object)
{
  m_mxEntityId = p_object.GetObjectId();
  m_atom = p_object.GetAtomId();
  AddToCurrentWorld();
  return SUCCESS;
}

// OFFSET: LEGO1 0x10010810 STUB
void LegoEntity::Destroy(MxBool p_fromDestructor)
{
  if (m_unk54) {
    // TODO
  }

  delete[] m_actionArgString;
  Reset();
}

// OFFSET: LEGO1 0x10010880 STUB
void LegoEntity::AddToCurrentWorld()
{
  LegoWorld* world = GetCurrentWorld();
  if (world != NULL && world != (LegoWorld*)this)
  {
    // TODO: world->vtable58(this);
  }
}

// OFFSET: LEGO1 0x10010e10
void LegoEntity::ParseAction(char *p_extra)
{
  char copy[1024];
  char actionValue[1024];
  strcpy(copy, p_extra);

  if (KeyValueStringParse(actionValue, g_strACTION, copy)) {
    m_actionType = MatchActionString(strtok(actionValue, g_parseExtraTokens));

    if (m_actionType != ExtraActionType_exit) {
      char *token = strtok(NULL, g_parseExtraTokens);

      m_actionArgString = new char[strlen(token) + 1];
      strcpy(m_actionArgString, token);

      if (m_actionType != ExtraActionType_run) {
        m_actionArgNumber = atoi(strtok(NULL, g_parseExtraTokens));
      }
    }
  }
}
