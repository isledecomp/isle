#include "legoactioncontrolpresenter.h"
#include "define.h"
#include "extra.h"
#include "legoomni.h"
#include "legoutil.h"
#include "mxmediapresenter.h"
#include "mxomni.h"
#include "mxticklemanager.h"
#include "mxtypes.h"
#include <cstdlib>
#include <cstring>

// Only a `scalar deleting destructor' exists.
LegoActionControlPresenter::~LegoActionControlPresenter() { Destroy(TRUE); }

// OFFSET: LEGO1 0x10043ce0 STUB
void LegoActionControlPresenter::ReadyTickle() {
  // TODO
}

// OFFSET: LEGO1 0x10043d40 STUB
void LegoActionControlPresenter::RepeatingTickle() {
  // TODO
}

// OFFSET: LEGO1 0x10043df0
MxResult LegoActionControlPresenter::AddToManager() {
  MxResult result = FAILURE;
  if (TickleManager()) {
    result = SUCCESS;
    TickleManager()->RegisterClient(this, 100);
  }

  return result;
}

// OFFSET: LEGO1 0x10043e20
void LegoActionControlPresenter::Destroy(MxBool p_fromDestructor) {
  if (TickleManager()) {
    TickleManager()->UnregisterClient(this);
  }

  if (!p_fromDestructor) {
    MxMediaPresenter::Destroy(FALSE);
  }
}

// OFFSET: LEGO1 0x10043e50
void LegoActionControlPresenter::ParseExtra() {
  MxU32 len = m_action->GetExtraLength();

  if (len == 0)
    return;

  len &= MAXWORD;

  char buf[1024];
  memcpy(buf, m_action->GetExtraData(), len);
  buf[len] = '\0';

  char output[1024];
  if (KeyValueStringParse(output, g_strACTION, buf)) {
    m_unk0x50 = MatchActionString(strtok(output, g_parseExtraTokens));
    if (m_unk0x50 != ExtraActionType_exit) {
      MakeSourceName(buf, strtok(NULL, g_parseExtraTokens));
      m_unk0x54 = buf;
      m_unk0x54.ToLowerCase();
      if (m_unk0x50 != ExtraActionType_run) {
        m_unk0x64 = atoi(strtok(NULL, g_parseExtraTokens));
      }
    }
  }
}
