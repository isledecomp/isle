#ifndef MXNOTIFICATIONMANAGER_H
#define MXNOTIFICATIONMANAGER_H

#include "mxcore.h"
#include "mxcriticalsection.h"
#include "mxtypes.h"

#include "compat.h"

class MxNotification
{
public:
  MxNotification(MxCore *p_target, MxParam *p_param);
  ~MxNotification();

  inline MxCore *GetTarget()
  {
    return m_target;
  }

  inline MxParam *GetParam()
  {
    return m_param;
  }

private:
  MxCore *m_target; // 0x0
  MxParam *m_param; // 0x4
};

class MxIdList : public list<MxU32>
{};

class MxNotificationPtrList : public list<MxNotification *>
{};

// VTABLE 0x100dc078
class MxNotificationManager : public MxCore
{
private:
  MxNotificationPtrList *m_queue; // 0x8
  MxNotificationPtrList *m_sendList; // 0xc
  MxCriticalSection m_lock; // 0x10
  MxS32 m_unk2c; // 0x2c
  MxIdList m_listenerIds; // 0x30
  MxBool m_active; // 0x3c

public:
  MxNotificationManager();
  virtual ~MxNotificationManager(); // vtable+0x0 (scalar deleting destructor)

  virtual MxResult Tickle(); // vtable+0x8
  // TODO: Where does this method come from?
  virtual MxResult Create(MxS32 p_unk1, MxS32 p_unk2); // vtable+0x14
  void Register(MxCore *p_listener);
  void Unregister(MxCore *p_listener);
  MxResult Send(MxCore *p_listener, MxParam *p_param);

private:
  void FlushPending(MxCore *p_listener);
};

#endif // MXNOTIFICATIONMANAGER_H
