#include "legoentity.h"

#include "legoomni.h"
#include "legoutil.h"
#include "define.h"

DECOMP_SIZE_ASSERT(LegoEntity, 0x68)

// OFFSET: LEGO1 0x1000c290
LegoEntity::~LegoEntity()
{
  Destroy();
}

// OFFSET: LEGO1 0x100114f0 STUB
MxLong LegoEntity::Notify(MxParam &p)
{
  // TODO

  return 0;
}

// OFFSET: LEGO1 0x100107e0 STUB
void LegoEntity::vtable18()
{

}

// OFFSET: LEGO1 0x10010810 STUB
void LegoEntity::Destroy()
{
  // TODO
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
