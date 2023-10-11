#ifndef MXNOTIFICATIONPARAM_H
#define MXNOTIFICATIONPARAM_H

#include "compat.h"
#include "mxparam.h"
#include "mxtypes.h"

class MxCore;

enum MxParamType
{
  MXSTREAMER_UNKNOWN = 2,
  MXPRESENTER_NOTIFICATION = 5,
  MXSTREAMER_DELETE_NOTIFY = 6,
  MXTRANSITIONMANAGER_TRANSITIONENDED = 24
};

// VTABLE 0x100d56e0
class MxNotificationParam : public MxParam
{
public:
  inline MxNotificationParam(MxParamType p_type, MxCore *p_sender) : MxParam(), m_type(p_type), m_sender(p_sender){}

  virtual ~MxNotificationParam() override {} // vtable+0x0 (scalar deleting destructor)
  virtual MxNotificationParam *Clone(); // vtable+0x4

  inline MxParamType GetType() const { return m_type; }
  inline MxCore *GetSender() const { return m_sender; }

protected:
  MxParamType m_type; // 0x4
  MxCore *m_sender; // 0x8
};

#endif // MXNOTIFICATIONPARAM_H
