#include "mxnotificationmanager.h"

#include "compat.h"
#include "decomp.h"
#include "mxautolock.h"
#include "mxmisc.h"
#include "mxnotificationparam.h"
#include "mxparam.h"
#include "mxticklemanager.h"
#include "mxtypes.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(MxNotification, 0x08);
DECOMP_SIZE_ASSERT(MxNotificationManager, 0x40);

// FUNCTION: LEGO1 0x100ac220
MxNotification::MxNotification(MxCore* p_target, const MxNotificationParam& p_param)
{
	m_target = p_target;
	m_param = p_param.Clone();
}

// FUNCTION: LEGO1 0x100ac240
MxNotification::~MxNotification()
{
	delete m_param;
}

// FUNCTION: LEGO1 0x100ac250
// FUNCTION: BETA10 0x10125805
MxNotificationManager::MxNotificationManager() : MxCore(), m_lock(), m_listenerIds()
{
	m_unk0x2c = 0;
	m_postNotificationQueue = NULL;
	m_active = TRUE;
	m_flashQueue = NULL;
}

// FUNCTION: LEGO1 0x100ac450
MxNotificationManager::~MxNotificationManager()
{
	AUTOLOCK(m_lock);
	Tickle();
	assert(m_postNotificationQueue->empty());
	assert(!m_flashQueue);
	delete m_postNotificationQueue;
	m_postNotificationQueue = NULL;

	TickleManager()->UnregisterClient(this);
}

// FUNCTION: LEGO1 0x100ac600
MxResult MxNotificationManager::Create(MxU32 p_frequencyMS, MxBool p_createThread)
{
	MxResult result = SUCCESS;
	m_postNotificationQueue = new MxNotificationPtrList();
	assert(m_postNotificationQueue);

	if (m_postNotificationQueue == NULL) {
		result = FAILURE;
	}
	else {
		TickleManager()->RegisterClient(this, 10);
	}

	return result;
}

// FUNCTION: LEGO1 0x100ac6c0
// FUNCTION: BETA10 0x10125b57
MxResult MxNotificationManager::Send(MxCore* p_listener, const MxNotificationParam& p_param)
{
	AUTOLOCK(m_lock);

	if (!m_active) {
		return FAILURE;
	}

	MxIdList::iterator it = find(m_listenerIds.begin(), m_listenerIds.end(), p_listener->GetId());
	if (it == m_listenerIds.end()) {
		assert("Post notification recipient not found!" == NULL);
		return FAILURE;
	}

	MxNotification* notification = new MxNotification(p_listener, p_param);
	assert(notification);

	if (notification != NULL) {
		m_postNotificationQueue->push_back(notification);
		return SUCCESS;
	}

	assert(0);
	return FAILURE;
}

// FUNCTION: LEGO1 0x100ac800
MxResult MxNotificationManager::Tickle()
{
	m_flashQueue = new MxNotificationPtrList();
	assert(m_flashQueue);

	if (m_flashQueue == NULL) {
		return FAILURE;
	}
	else {
		{
			AUTOLOCK(m_lock);
			assert(m_postNotificationQueue);
			MxNotificationPtrList* temp1 = m_postNotificationQueue;
			MxNotificationPtrList* temp2 = m_flashQueue;
			m_postNotificationQueue = temp2;
			m_flashQueue = temp1;
		}

		while (m_flashQueue->size() != 0) {
			MxNotification* notif = m_flashQueue->front();
			m_flashQueue->pop_front();
			notif->GetTarget()->Notify(*notif->GetParam());
			delete notif;
		}

		assert(m_flashQueue->empty());
		delete m_flashQueue;
		m_flashQueue = NULL;
		return SUCCESS;
	}
}

// FUNCTION: LEGO1 0x100ac990
void MxNotificationManager::FlushPending(MxCore* p_object)
{
	assert(p_object);
	assert(m_postNotificationQueue);

	MxNotificationPtrList flashQueue;
	MxNotification* notif;

	{
		AUTOLOCK(m_lock);

		// Find all notifications from, and addressed to, p_object.
		if (m_flashQueue != NULL) {
			MxNotificationPtrList::iterator it = m_flashQueue->begin();
			while (it != m_flashQueue->end()) {
				notif = *it;
				if (notif->GetTarget()->GetId() == p_object->GetId() ||
					(notif->GetParam()->GetSender() && notif->GetParam()->GetSender()->GetId() == p_object->GetId())) {
					m_flashQueue->erase(it++);
					flashQueue.push_back(notif);
				}
				else {
					it++;
				}
			}
		}

		MxNotificationPtrList::iterator it = m_postNotificationQueue->begin();
		while (it != m_postNotificationQueue->end()) {
			notif = *it;
			if (notif->GetTarget()->GetId() == p_object->GetId() ||
				(notif->GetParam()->GetSender() && notif->GetParam()->GetSender()->GetId() == p_object->GetId())) {
				m_postNotificationQueue->erase(it++);
				flashQueue.push_back(notif);
			}
			else {
				it++;
			}
		}
	}

	assert(flashQueue.size() < 500);

	// Deliver those notifications.
	while (flashQueue.size() != 0) {
		notif = flashQueue.front();
		flashQueue.pop_front();
		notif->GetTarget()->Notify(*notif->GetParam());
		delete notif;
	}
}

// FUNCTION: LEGO1 0x100acd20
// STUB: BETA10 0x1012666a
void MxNotificationManager::Register(MxCore* p_listener)
{
	AUTOLOCK(m_lock);

	MxIdList::iterator it = find(m_listenerIds.begin(), m_listenerIds.end(), p_listener->GetId());
	if (it != m_listenerIds.end()) {
		return;
	}

	m_listenerIds.push_back(p_listener->GetId());
}

// FUNCTION: LEGO1 0x100acdf0
// FUNCTION: BETA10 0x10126785
void MxNotificationManager::Unregister(MxCore* p_listener)
{
	AUTOLOCK(m_lock);

	MxIdList::iterator it = find(m_listenerIds.begin(), m_listenerIds.end(), p_listener->GetId());

	if (it != m_listenerIds.end()) {
		m_listenerIds.erase(it);
		FlushPending(p_listener);
	}
}
