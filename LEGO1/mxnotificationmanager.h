#ifndef MXNOTIFICATIONMANAGER_H
#define MXNOTIFICATIONMANAGER_H

#include <STL.H>

#include "mxcore.h"
#include "mxcriticalsection.h"
#include "mxtypes.h"

class MxNotification
{
public:
  MxCore *m_destination;
  MxParam *m_param;

  MxNotification(MxCore *p_destination, MxParam *p_param);
  ~MxNotification();
};

// VTABLE 0x100dc078
class MxNotificationManager : public MxCore
{
private:
  List<MxNotification *> *m_queue; // 0x8
  List<MxNotification *> *m_sendList; // 0xc
  MxCriticalSection m_lock; // 0x10
  int m_unk2c; // 0x2c
  List<unsigned int> m_listenerIds; // 0x30
  MxBool m_active; // 0x3c

public:
  MxNotificationManager();
  virtual ~MxNotificationManager(); // vtable+0x0

  virtual long Tickle(); // vtable+0x8
  // TODO: Where does this method come from?
  virtual MxResult Create(int p_unk1, int p_unk2); // vtable+0x14
  void Register(MxCore *p_listener);
  void Unregister(MxCore *p_listener);
  MxResult Send(MxCore *p_listener, MxParam *p_param);

private:
  void FlushPending(MxCore *p_listener);
};

#endif // MXNOTIFICATIONMANAGER_H
