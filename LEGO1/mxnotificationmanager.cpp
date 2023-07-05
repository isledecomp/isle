#include "legoomni.h"
#include "mxautolocker.h"
#include "mxnotificationmanager.h"
#include "mxtypes.h"

// OFFSET: LEGO1 0x100ac220 STUB
MxNotification::MxNotification(MxCore *p_destination, void *p_vtable)
{
  m_destination = p_destination;
  // TODO: Call p_vtable+0x4, assign result to m_param.
  m_param = NULL;
}

// OFFSET: LEGO1 0x100ac240 STUB
MxNotification::~MxNotification()
{
  // TODO
  //delete m_param;
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

  MxTickleManager *tickleManager = TickleManager();
  // TODO
  //tickleManager->Unregister(this);
  tickleManager->vtable18();
}

// OFFSET: LEGO1 0x100ac800
long MxNotificationManager::Tickle()
{
  m_sendList = new List<MxNotification *>();
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
      notif->m_destination->Notify(*notif->m_param);
      delete notif;
    }

    delete m_sendList;
    m_sendList = NULL;
    return SUCCESS;
  }
}

// OFFSET: LEGO1 0x100ac600
MxResult MxNotificationManager::Create(int p_unk1, int p_unk2)
{
  MxResult result = SUCCESS;
  m_queue = new List<MxNotification *>();

  if (m_queue == NULL) {
    result = FAILURE;
  }
  else {
    MxTickleManager *tickleManager = TickleManager();
    // TODO
    //tickleManager->Register(this, 10);
    tickleManager->vtable14();
  }

  return result;
}

// OFFSET: LEGO1 0x100acd20
void MxNotificationManager::Register(MxCore *p_listener)
{
  unsigned int listenerId;
  List<unsigned int>::iterator it;
  MxAutoLocker lock(&m_lock);

  listenerId = p_listener->GetId();
  it = find(m_listenerIds.begin(), m_listenerIds.end(), listenerId);
  if (it != m_listenerIds.end())
    return;

  m_listenerIds.push_back(listenerId);
}

// OFFSET: LEGO1 0x100acdf0
void MxNotificationManager::Unregister(MxCore *p_listener)
{
  MxAutoLocker lock(&m_lock);

  unsigned int listenerId = p_listener->GetId();
  List<unsigned int>::iterator it = find(m_listenerIds.begin(), m_listenerIds.end(), listenerId);

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
MxResult MxNotificationManager::Send(MxCore *p_listener, void *p_vtable)
{
  MxAutoLocker lock(&m_lock);

  if (m_active == FALSE) {
    return FAILURE;
  }
  else {
    List<unsigned int>::iterator it = find(m_listenerIds.begin(), m_listenerIds.end(), p_listener->GetId());
    if (it == m_listenerIds.end()) {
      return FAILURE;
    }
    else {
      MxNotification *notif = new MxNotification(p_listener, p_vtable);
      if (notif != NULL) {
        m_queue->push_back(notif);
        return SUCCESS;
      }
    }
  }

  return FAILURE;
}
