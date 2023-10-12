#include "mxomni.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "mxtypes.h"

#include "decomp.h"

#define TICKLE_MANAGER_FLAG_DESTROY 0x1

DECOMP_SIZE_ASSERT(MxTickleClient, 0x10);
DECOMP_SIZE_ASSERT(MxTickleManager, 0x14);

// OFFSET: LEGO1 0x100bdd10
MxTickleClient::MxTickleClient(MxCore *p_client, MxTime p_interval)
{
  m_flags = 0;
  m_client = p_client;
  m_interval = p_interval;
  m_lastUpdateTime = -m_interval;
}

// OFFSET: LEGO1 0x100bdd30
MxTickleManager::~MxTickleManager()
{
  while (m_clients.size() != 0) {
    MxTickleClient *client = m_clients.front();
    m_clients.pop_front();
    delete client;
  }
}

// TODO: Match.
// OFFSET: LEGO1 0x100bdde0
MxResult MxTickleManager::Tickle()
{
  MxTime time = Timer()->GetTime();

  MxTickleClientPtrList::iterator it = m_clients.begin();

  while (it != m_clients.end()) {
    MxTickleClient *client = *it;
    if ((client->GetFlags() & TICKLE_MANAGER_FLAG_DESTROY) == 0) {
      if (client->GetLastUpdateTime() >= time)
        client->SetLastUpdateTime(-client->GetTickleInterval());

      if ((client->GetTickleInterval() + client->GetLastUpdateTime()) < time) {
        client->GetClient()->Tickle();
        client->SetLastUpdateTime(time);
      }

      it++;
    }
    else {
      m_clients.erase(it++);
      delete client;
    }
  }

  return SUCCESS;
}

// OFFSET: LEGO1 0x100bde80
void MxTickleManager::RegisterClient(MxCore *p_client, MxTime p_interval)
{
  MxTime interval = GetClientTickleInterval(p_client);
  if (interval == TICKLE_MANAGER_NOT_FOUND) {
    MxTickleClient *client = new MxTickleClient(p_client, p_interval);
    if (client != NULL)
      m_clients.push_back(client);
  }
}

// OFFSET: LEGO1 0x100bdf60
void MxTickleManager::UnregisterClient(MxCore *p_client)
{
  MxTickleClientPtrList::iterator it = m_clients.begin();
  while (it != m_clients.end()) {
    MxTickleClient *client = *it;
    if (client->GetClient() == p_client) {
      client->SetFlags(client->GetFlags() | TICKLE_MANAGER_FLAG_DESTROY);
      return;
    }

    it++;
  }
}

// OFFSET: LEGO1 0x100bdfa0
void MxTickleManager::SetClientTickleInterval(MxCore *p_client, MxTime p_interval)
{
  for (MxTickleClientPtrList::iterator it = m_clients.begin(); it != m_clients.end(); it++) {
    MxTickleClient *client = *it;
    if ((client->GetClient() == p_client) && ((client->GetFlags() & TICKLE_MANAGER_FLAG_DESTROY) == 0)) {
      client->SetTickleInterval(p_interval);
      return;
    }
  }
}

// OFFSET: LEGO1 0x100be000
MxTime MxTickleManager::GetClientTickleInterval(MxCore *p_client)
{
  MxTickleClientPtrList::iterator it = m_clients.begin();
  while (it != m_clients.end()) {
    MxTickleClient *client = *it;
    if ((client->GetClient() == p_client) && ((client->GetFlags() & TICKLE_MANAGER_FLAG_DESTROY) == 0))
      return client->GetTickleInterval();

    it++;
  }

  return TICKLE_MANAGER_NOT_FOUND;
}
