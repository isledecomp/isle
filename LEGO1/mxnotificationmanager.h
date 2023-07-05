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

    MxNotification(MxCore *p_destination, void *p_vtable);
    ~MxNotification();
};

// VTABLE 0x100dc078
class MxNotificationManager : public MxCore
{
  private:
    List<MxNotification *> *m_queue;
    List<MxNotification *> *m_sendList;
    MxCriticalSection m_lock;
    int m_unk2c;
    List<unsigned int> m_listenerIds;
    MxBool m_active;

  public:
    MxNotificationManager();
    virtual ~MxNotificationManager(); // vtable+0x0

    virtual long Tickle(); // vtable+0x8
    // TODO: Where does this method come from?
    virtual MxResult Create(int p_unk1, int p_unk2); // vtable+0x14
    void Register(MxCore *p_listener);
    void Unregister(MxCore *p_listener);
    MxResult Send(MxCore *p_listener, void *p_vtable);

  private:
    void FlushPending(MxCore *p_listener);
};

#endif // MXNOTIFICATIONMANAGER_H
