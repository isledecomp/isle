#include "mxpresenter.h"
#include "mxautolocker.h"
#include "mxparam.h"
#include <string.h>

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxPresenter, 0x40);

// 0x10101eac
char *g_pParseExtraTokens = ":;";

// 0x10101edc
char *g_strWORLD = "WORLD";

// OFFSET: LEGO1 0x1000be30
void MxPresenter::VTable0x14()
{
}

// OFFSET: LEGO1 0x1000be40
void MxPresenter::VTable0x18()
{
  ParseExtra();
  m_unk0xc |= 1 << (unsigned char)m_unk0x8;
  m_unk0x8 = 2;
}

// OFFSET: LEGO1 0x1000be60
void MxPresenter::VTable0x1c()
{
  m_unk0xc |= 1 << (unsigned char)m_unk0x8;
  m_unk0x8 = 3;
}

// OFFSET: LEGO1 0x1000be80
void MxPresenter::VTable0x20()
{
  m_unk0xc |= 1 << (unsigned char)m_unk0x8;
  m_unk0x8 = 4;
}

// OFFSET: LEGO1 0x1000bea0
void MxPresenter::VTable0x24()
{
  m_unk0xc |= 1 << (unsigned char)m_unk0x8;
  m_unk0x8 = 5;
}

// OFFSET: LEGO1 0x1000bec0
void MxPresenter::VTable0x28()
{
  m_unk0xc |= 1 << (unsigned char)m_unk0x8;
  m_unk0x8 = 6;
}

// OFFSET: LEGO1 0x1000bee0
void MxPresenter::DoneTickle()
{
  m_unk0xc |= (1 << m_unk0x8);
  m_unk0x8 = 0;
}

// OFFSET: LEGO1 0x1000bf00
MxPresenter::~MxPresenter()
{
}

// OFFSET: LEGO1 0x1000bf70
undefined4 MxPresenter::VTable0x34()
{
  return 0;
}

// OFFSET: LEGO1 0x1000bf80
void MxPresenter::InitVirtual()
{
  Init();
}

// OFFSET: LEGO1 0x1000bf90
void MxPresenter::VTable0x44(undefined4 param)
{
  m_unk0xc |= 1 << (unsigned char)m_unk0x8;
  m_unk0x8 = param;
}

// OFFSET: LEGO1 0x1000bfb0
unsigned char MxPresenter::VTable0x48(unsigned char param)
{
  return m_unk0xc & (1 << param);
}

// OFFSET: LEGO1 0x1000bfc0
undefined4 MxPresenter::VTable0x4c()
{
  return 0;
}

// OFFSET: LEGO1 0x1000bfd0
undefined MxPresenter::VTable0x50(undefined4, undefined4)
{
  return 0;
}

// OFFSET: LEGO1 0x100b4d50
void MxPresenter::Init()
{
  m_unk0x8 = 0;
  m_action = NULL;
  m_unk0x18 = 0;
  m_unk0x3c = 0;
  m_unk0xc = 0;
  m_unk0x10 = 0;
  m_unk0x14 = 0;
}

// OFFSET: LEGO1 0x100b4d80 STUB
MxLong MxPresenter::StartAction(MxStreamController *, MxDSAction *)
{
  // TODO

  return 0;
}

// OFFSET: LEGO1 0x100b4e40 STUB
void MxPresenter::EndAction()
{
  // TODO
}

// OFFSET: LEGO1 0x100b4fc0
void MxPresenter::ParseExtra()
{
  MxAutoLocker lock(&m_criticalSection);

  // TODO: this part isn't matching. wrong type for this variable?
  MxU16 len = m_action->GetUnkLength();

  if (len != 0) {
    char t_actionData[512];
    memcpy(t_actionData, m_action->GetUnkData(), len & MAXWORD);
    t_actionData[len] = '\0';

    char t_worldSection[512];
    if (FUN_100b7050(t_worldSection, g_strWORLD, t_actionData)) {
      char *token = strtok(t_worldSection, g_pParseExtraTokens);
      char t_token[256];
      strcpy(t_token, token);

      token = strtok(NULL, g_pParseExtraTokens);
      int val = token ? atoi(token) : 0;

      int result = MxOmni::GetInstance()->vtable0x30(t_token, val, this);
      
      // TODO: magic number for flag
      m_action->SetFlags(m_action->GetFlags() | 128);
      
      if (result)
        FUN_100b5120(MxOmni::GetInstance());

    }
  }
}

// OFFSET: LEGO1 0x100b5120
void MxPresenter::FUN_100b5120(MxOmni *p_omni)
{
  if (m_unk0x3c) {
    MxAutoLocker lock(&m_criticalSection);

    // TODO: remove cast once member type is understood
    // TOOD: magic number used for notification type. replace with enum
    NotificationManager()->Send((MxCore*)m_unk0x3c, &MxParam(5, this));

    m_action->SetOmni(p_omni ? p_omni : MxOmni::GetInstance());
    m_unk0x3c = 0;
  }
}

// OFFSET: LEGO1 0x100b5200
MxLong MxPresenter::Tickle()
{
  MxAutoLocker lock(&m_criticalSection);

  switch (m_unk0x8) {
    case 1:
      VTable0x18();
      if (m_unk0x8 != 2)
        break;

    case 2:
      VTable0x1c();
      if (m_unk0x8 != 3)
        break;

    case 3:
      VTable0x20();
      if (m_unk0x8 != 4)
        break;

    case 4:
      VTable0x24();
      if (m_unk0x8 != 5)
        break;

    case 5:
      VTable0x28();
      if (m_unk0x8 != 6)
        break;

    case 6:
      DoneTickle();
  }

  return 0;
}

// OFFSET: LEGO1 0x100b52d0
void MxPresenter::Enable(MxBool p_shouldEnable)
{
  // TODO: magic number for flag
  if (m_action && p_shouldEnable != ActionIsEnabled()) {
    DWORD flags = m_action->GetFlags();
    if (p_shouldEnable) {
      m_action->SetFlags(flags | 32);
    } else {
      m_action->SetFlags(flags & ~32);
    }
  }
}

// OFFSET: LEGO1 0x100b54c0
MxBool MxPresenter::ActionIsEnabled()
{
  // TODO: magic number for flag
  // TODO: making an assumption that bit 5 means "enabled"
  return m_action && (m_action->GetFlags() & 32);
}

// OFFSET: LEGO1 0x100b7050
MxBool FUN_100b7050(char *p_str0, char *p_str1, char *p_str2)
{
  MxBool didMatch = FALSE;

  MxS16 len = strlen(p_str2);
  char *temp = new char[len + 1];
  strcpy(temp, p_str2);

  char *token = strtok(temp, ", \t\r\n:");
  while (token) {
    len -= (strlen(token) + 1);

    if (strcmpi(token, p_str1) == 0) {
      if (p_str0 && len > 0) {
        char *cur = &token[strlen(p_str1)];
        cur++;
        while (*cur != ',') {
          if (*cur == ' ' || *cur == '\0' || *cur == '\t' || *cur == '\n' || *cur == '\r')
            break;
          *p_str0++ = *cur++;
        }
        *p_str0 = '\0';
      }

      didMatch = TRUE;
      break;
    }

    token = strtok(NULL, ", \t\r\n:");
  }

  delete[] temp;
  return didMatch;
}
