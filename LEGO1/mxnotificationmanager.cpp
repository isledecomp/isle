#include "legoomni.h"
#include "mxautolocker.h"
#include "mxcore.h"
#include "mxnotificationmanager.h"
#include "mxparam.h"
#include "mxtypes.h"

#include "decomp.h"
#include "stlcompat.h"

DECOMP_SIZE_ASSERT(MxNotification, 0x8);
// Can't use DECOMP_SIZE_ASSERT due to STL type size changes.
//DECOMP_SIZE_ASSERT(MxNotificationManager, 0x40);

// OFFSET: LEGO1 0x100ac220
MxNotification::MxNotification(MxCore *p_target, MxParam *p_param)
{
  m_target = p_target;
  m_param = p_param->Clone();
}

// OFFSET: LEGO1 0x100ac240
MxNotification::~MxNotification()
{
  delete m_param;
}

// OFFSET: LEGO1 0x100ac250
MxNotificationManager::MxNotificationManager() : MxCore(), m_lock(), m_listenerIds()
{
  m_unk2c = 0;
  m_queue = NULL;
  m_active = TRUE;
  m_sendList = NULL;
}

// OFFSET: LEGO1 0x100ac450
MxNotificationManager::~MxNotificationManager()
{
  MxAutoLocker lock(&m_lock);
  Tickle();
  delete m_queue;
  m_queue = NULL;

  TickleManager()->Unregister(this);
}

// OFFSET: LEGO1 0x100ac800
MxResult MxNotificationManager::Tickle()
{
  m_sendList = new MxNotificationPtrList();
  if (m_sendList == NULL) {
    return FAILURE;
  }
  else {
    {
      MxAutoLocker lock(&m_lock);
      swap(m_queue, m_sendList);
    }

    while (m_sendList->size() != 0) {
      MxNotification *notif = m_sendList->front();
      m_sendList->pop_front();
      notif->GetTarget()->Notify(*notif->GetParam());
      delete notif;
    }

    delete m_sendList;
    m_sendList = NULL;
    return SUCCESS;
  }
}

// OFFSET: LEGO1 0x100ac600
MxResult MxNotificationManager::Create(MxS32 p_unk1, MxS32 p_unk2)
{
  MxResult result = SUCCESS;
  m_queue = new MxNotificationPtrList();

  if (m_queue == NULL) {
    result = FAILURE;
  }
  else {
    TickleManager()->Register(this, 10);
  }

  return result;
}

// OFFSET: LEGO1 0x100acd20
void MxNotificationManager::Register(MxCore *p_listener)
{
  MxAutoLocker lock(&m_lock);

  MxU32 listenerId = p_listener->GetId();
  MxIdList::iterator it = find(m_listenerIds.begin(), m_listenerIds.end(), listenerId);
  if (it != m_listenerIds.end())
    return;

  m_listenerIds.push_back(listenerId);
}

// OFFSET: LEGO1 0x100acdf0
void MxNotificationManager::Unregister(MxCore *p_listener)
{
  MxAutoLocker lock(&m_lock);

  MxIdList::iterator it = find(m_listenerIds.begin(), m_listenerIds.end(), p_listener->GetId());

  if (it != m_listenerIds.end()) {
    m_listenerIds.erase(it);
    FlushPending(p_listener);
  }
}

// OFFSET: LEGO1 0x100ac990 STUB
void MxNotificationManager::FlushPending(MxCore *p_listener)
{
  // TODO
}

// OFFSET: LEGO1 0x100ac6c0
MxResult MxNotificationManager::Send(MxCore *p_listener, MxParam *p_param)
{
  MxAutoLocker lock(&m_lock);

  if (m_active == FALSE) {
    return FAILURE;
  }
  else {
    MxIdList::iterator it = find(m_listenerIds.begin(), m_listenerIds.end(), p_listener->GetId());
    if (it == m_listenerIds.end()) {
      return FAILURE;
    }
    else {
      MxNotification *notif = new MxNotification(p_listener, p_param);
      if (notif != NULL) {
        m_queue->push_back(notif);
        return SUCCESS;
      }
    }
  }

  return FAILURE;
}
