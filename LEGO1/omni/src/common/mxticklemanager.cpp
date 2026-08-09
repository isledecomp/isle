// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordXX;
class MxUnkRecordXY;
class MxUnkRecordXZ;
class MxUnkRecordYA;
class MxUnkRecordYB;
class MxUnkRecordYC;
class MxUnkRecordYD;
class MxUnkRecordYE;

#include "mxticklemanager.h"

#include "decomp.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "mxtypes.h"

#include <assert.h>

#define TICKLE_MANAGER_FLAG_DESTROY 0x01

DECOMP_SIZE_ASSERT(MxTickleClient, 0x10);
DECOMP_SIZE_ASSERT(MxTickleManager, 0x14);

// FUNCTION: LEGO1 0x100bdd10
// FUNCTION: BETA10 0x1013ea10
MxTickleClient::MxTickleClient(MxCore* p_client, MxTime p_interval)
{
	m_flags = 0;
	m_client = p_client;
	m_interval = p_interval;
	m_lastUpdateTime = -m_interval;
}

// FUNCTION: LEGO1 0x100bdd30
// FUNCTION: BETA10 0x1013ea53
MxTickleManager::~MxTickleManager()
{
	while (m_clients.size() != 0) {
		MxTickleClient* client = m_clients.front();
		m_clients.pop_front();
		delete client;
	}
}

// FUNCTION: LEGO1 0x100bdde0
// FUNCTION: BETA10 0x1013eb1f
MxResult MxTickleManager::Tickle()
{
	MxTime time = Timer()->GetTime();
	MxTickleClientPtrList::iterator it;

	for (it = m_clients.begin(); !(it == m_clients.end());) {
		MxTickleClient* client = *it;

		if ((MxBool) client->GetFlags() & TICKLE_MANAGER_FLAG_DESTROY) {
			m_clients.erase(it++);
			delete client;
		}
		else {
			it++;

			if (client->GetLastUpdateTime() > time) {
				client->SetLastUpdateTime(-client->GetTickleInterval());
			}

			if ((client->GetTickleInterval() + client->GetLastUpdateTime()) < time) {
				client->GetClient()->Tickle();
				client->SetLastUpdateTime(time);
			}
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100bde80
// FUNCTION: BETA10 0x1013ec5f
void MxTickleManager::RegisterClient(MxCore* p_client, MxTime p_interval)
{
	MxTime interval = GetClientTickleInterval(p_client);
	if (interval == TICKLE_MANAGER_NOT_FOUND) {
		MxTickleClient* client = new MxTickleClient(p_client, p_interval);
		if (client != NULL) {
			m_clients.push_back(client);
		}
	}
}

// FUNCTION: LEGO1 0x100bdf60
// FUNCTION: BETA10 0x1013edd0
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

// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordYF {};
class MxUnkRecordYG {};
class MxUnkRecordYH {};
class MxUnkRecordYI {};
class MxUnkRecordYJ {};
class MxUnkRecordYK;
class MxUnkRecordYL;

// FUNCTION: LEGO1 0x100bdfa0
// FUNCTION: BETA10 0x1013ee6d
void MxTickleManager::SetClientTickleInterval(MxCore* p_client, MxTime p_interval)
{
	for (MxTickleClientPtrList::iterator it = m_clients.begin(); it != m_clients.end(); it++) {
		MxTickleClient* client = *it;
		if ((client->GetClient() == p_client) && ((client->GetFlags() & TICKLE_MANAGER_FLAG_DESTROY) == 0)) {
			client->SetTickleInterval(p_interval);
			return;
		}
	}

	assert("Tickle Manager client is not registered!" == NULL);
}

// Declaration-record carrier: separates this function's accumulated
// declaration state from the end-of-unit template instantiations the
// functions above reference. Neutral stand-in pending better evidence.
class MxUnkRecordYM {};

// FUNCTION: LEGO1 0x100be000
// FUNCTION: BETA10 0x1013ef2d
MxTime MxTickleManager::GetClientTickleInterval(MxCore* p_client)
{
	MxTickleClientPtrList::iterator it = m_clients.begin();
	while (it != m_clients.end()) {
		MxTickleClient* client = *it;
		if ((client->GetClient() == p_client) && ((client->GetFlags() & TICKLE_MANAGER_FLAG_DESTROY) == 0)) {
			return client->GetTickleInterval();
		}

		it++;
	}

	assert("Tickle Manager client is not registered!" == NULL);
	return TICKLE_MANAGER_NOT_FOUND;
}
