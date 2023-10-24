#ifndef MXACTIONNOTIFICATIONPARAM_H
#define MXACTIONNOTIFICATIONPARAM_H

#include "mxnotificationparam.h"
#include "mxdsaction.h"

// VTABLE 0x100d8350
// SIZE 0x14
class MxActionNotificationParam : public MxNotificationParam
{
public:
  inline MxActionNotificationParam(MxParamType p_type, MxCore *p_sender, MxDSAction *p_action, MxBool p_reallocAction) : MxNotificationParam(p_type, p_sender)
  {
    MxDSAction *oldAction = p_action;
    this->m_realloc = p_reallocAction;

    if (p_reallocAction)
      this->m_action = new MxDSAction();
    else {
      this->m_action = oldAction;
      return;
    }

    this->m_action->SetAtomId(oldAction->GetAtomId());
    this->m_action->SetObjectId(oldAction->GetObjectId());
    this->m_action->SetUnknown24(oldAction->GetUnknown24());
  }

  // OFFSET: LEGO1 0x10051050
  inline virtual ~MxActionNotificationParam() override
  {
    if (!this->m_realloc)
      return;

    if (this->m_action)
      delete this->m_action;
  }

  virtual MxNotificationParam *Clone() override; // vtable+0x4

  inline MxDSAction *GetAction() { return m_action; }

protected:
  MxDSAction *m_action; // 0xc
  MxBool m_realloc; // 0x10
};

// VTABLE 0x100d8358
// SIZE 0x14
class MxEndActionNotificationParam : public MxActionNotificationParam
{
public:
  inline MxEndActionNotificationParam(MxParamType p_type, MxCore *p_sender, MxDSAction *p_action, MxBool p_reallocAction)
      : MxActionNotificationParam(p_type, p_sender, p_action, p_reallocAction) {}

  inline virtual ~MxEndActionNotificationParam() override {}; // 0x100513a0

  virtual MxNotificationParam *Clone() override; // vtable+0x4
};

#endif
