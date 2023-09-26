#include "legoomni.h"
#include "mxautolocker.h"
#include "mxcore.h"
#include "mxnotificationmanager.h"

// OFFSET: LEGO1 0x100ac320 TEMPLATE
// list<unsigned int,allocator<unsigned int> >::~list<unsigned int,allocator<unsigned int> >

// FIXME: Example of template compare functionality, remove before merging.
#include <stl.h>
#include <iostream>
void make_a_list() {
  List<unsigned int> l;
  cout << l.size();
}

// OFFSET: LEGO1 0x100ac450 STUB
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

// OFFSET: LEGO1 0x100ac800 STUB
MxLong MxNotificationManager::Tickle()
{
  // TODO

  return 0;
}
