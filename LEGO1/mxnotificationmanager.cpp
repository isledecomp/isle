#include "mxnotificationmanager.h"

#include "legoomni.h"
#include "mxautolocker.h"
#include "mxticklemanager.h"
#include "mxparam.h"
#include "mxtypes.h"

#include "compat.h"
#include "decomp.h"

DECOMP_SIZE_ASSERT(MxNotification, 0x8);
DECOMP_SIZE_ASSERT(MxNotificationManager, 0x40);

// OFFSET: LEGO1 0x100ac220
MxNotification::MxNotification(MxCore *p_target, MxNotificationParam *p_param)
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

  TickleManager()->UnregisterClient(this);
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
MxResult MxNotificationManager::Create(MxU32 p_frequencyMS, MxBool p_createThread)
{
  MxResult result = SUCCESS;
  m_queue = new MxNotificationPtrList();

  if (m_queue == NULL) {
    result = FAILURE;
  }
  else {
    TickleManager()->RegisterClient(this, 10);
  }

  return result;
}

// OFFSET: LEGO1 0x100acd20
void MxNotificationManager::Register(MxCore *p_listener)
{
  MxAutoLocker lock(&m_lock);

  MxIdList::iterator it = find(m_listenerIds.begin(), m_listenerIds.end(), p_listener->GetId());
  if (it != m_listenerIds.end())
    return;

  m_listenerIds.push_back(p_listener->GetId());
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

// OFFSET: LEGO1 0x100ac990
void MxNotificationManager::FlushPending(MxCore *p_listener)
{
  MxNotificationPtrList pending;
  MxNotification *notif;

  {
    MxAutoLocker lock(&m_lock);

    // Find all notifications from, and addressed to, p_listener.
    if (m_sendList != NULL) {
      MxNotificationPtrList::iterator it = m_sendList->begin();
      while (it != m_sendList->end()) {
        notif = *it;
        if ((notif->GetTarget()->GetId() == p_listener->GetId()) ||
            (notif->GetParam()->GetSender()) && (notif->GetParam()->GetSender()->GetId() == p_listener->GetId())) {
          m_sendList->erase(it++);
          pending.push_back(notif);
        }
        else {
          it++;
        }
      }
    }

    MxNotificationPtrList::iterator it = m_queue->begin();
    while (it != m_queue->end()) {
      notif = *it;
      if ((notif->GetTarget()->GetId() == p_listener->GetId()) ||
          (notif->GetParam()->GetSender()) && (notif->GetParam()->GetSender()->GetId() == p_listener->GetId())) {
        m_queue->erase(it++);
        pending.push_back(notif);
      }
      else {
        it++;
      }
    }
  }

  // Deliver those notifications.
  while (pending.size() != 0) {
    notif = pending.front();
    pending.pop_front();
    notif->GetTarget()->Notify(*notif->GetParam());
    delete notif;
  }
}

// OFFSET: LEGO1 0x100ac6c0
MxResult MxNotificationManager::Send(MxCore *p_listener, MxNotificationParam *p_param)
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