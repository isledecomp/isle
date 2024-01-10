#include "mxticklemanager.h"

#include "decomp.h"
#include "mxomni.h"
#include "mxtimer.h"
#include "mxtypes.h"

#define TICKLE_MANAGER_FLAG_DESTROY 0x1

DECOMP_SIZE_ASSERT(MxTickleClient, 0x10);
DECOMP_SIZE_ASSERT(MxTickleManager, 0x14);

// FUNCTION: LEGO1 0x100bdd10
MxTickleClient::MxTickleClient(MxCore* p_client, MxTime p_interval)
{
	m_flags = 0;
	m_client = p_client;
	m_interval = p_interval;
	m_lastUpdateTime = -m_interval;
}

// FUNCTION: LEGO1 0x100bdd30
MxTickleManager::~MxTickleManager()
{
	while (m_clients.size() != 0) {
		MxTickleClient* client = m_clients.front();
		m_clients.pop_front();
		delete client;
	}
}

// FUNCTION: LEGO1 0x100bdde0
MxResult MxTickleManager::Tickle()
{
	MxTime time = Timer()->GetTime();

	for (MxTickleClientPtrList::iterator it = m_clients.begin(); it != m_clients.end();) {
		MxTickleClient* client = *it;

		// TODO: Match.
		if ((MxU8) client->GetFlags() & TICKLE_MANAGER_FLAG_DESTROY) {
			m_clients.erase(it++);
			delete client;
		}
		else {
			it++;

			if (client->GetLastUpdateTime() > time)
				client->SetLastUpdateTime(-client->GetTickleInterval());

			if ((client->GetTickleInterval() + client->GetLastUpdateTime()) < time) {
				client->GetClient()->Tickle();
				client->SetLastUpdateTime(time);
			}
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100bde80
void MxTickleManager::RegisterClient(MxCore* p_client, MxTime p_interval)
{
	MxTime interval = GetClientTickleInterval(p_client);
	if (interval == TICKLE_MANAGER_NOT_FOUND) {
		MxTickleClient* client = new MxTickleClient(p_client, p_interval);
		if (client != NULL)
			m_clients.push_back(client);
	}
}

// FUNCTION: LEGO1 0x100bdf60
void MxTickleManager::UnregisterClient(MxCore* p_client)
{
	MxTickleClientPtrList::iterator it = m_clients.begin();
	while (it != m_clients.end()) {
		MxTickleClient* client = *it;
		if (client->GetClient() == p_client) {
			client->SetFlags(client->GetFlags() | TICKLE_MANAGER_FLAG_DESTROY);
			return;
		}

		it++;
	}
}

// FUNCTION: LEGO1 0x100bdfa0
void MxTickleManager::SetClientTickleInterval(MxCore* p_client, MxTime p_interval)
{
	for (MxTickleClientPtrList::iterator it = m_clients.begin(); it != m_clients.end(); it++) {
		MxTickleClient* client = *it;
		if ((client->GetClient() == p_client) && ((client->GetFlags() & TICKLE_MANAGER_FLAG_DESTROY) == 0)) {
			client->SetTickleInterval(p_interval);
			return;
		}
	}
}

// FUNCTION: LEGO1 0x100be000
MxTime MxTickleManager::GetClientTickleInterval(MxCore* p_client)
{
	MxTickleClientPtrList::iterator it = m_clients.begin();
	while (it != m_clients.end()) {
		MxTickleClient* client = *it;
		if ((client->GetClient() == p_client) && ((client->GetFlags() & TICKLE_MANAGER_FLAG_DESTROY) == 0))
			return client->GetTickleInterval();

		it++;
	}

	return TICKLE_MANAGER_NOT_FOUND;
}
