#include "mxstreamcontroller.h"

#include "mxautolock.h"
#include "mxdebug.h"
#include "mxdsmultiaction.h"
#include "mxdsstreamingaction.h"
#include "mxmisc.h"
#include "mxnextactiondatastart.h"
#include "mxstl/stlcompat.h"
#include "mxstreamchunk.h"
#include "mxstreamprovider.h"
#include "mxtimer.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(MxStreamController, 0x64)
DECOMP_SIZE_ASSERT(MxNextActionDataStart, 0x14)
DECOMP_SIZE_ASSERT(MxNextActionDataStartList, 0x0c)

// FUNCTION: LEGO1 0x100c0b90
MxStreamController::MxStreamController()
{
	m_provider = NULL;
	m_unk0x2c = NULL;
	m_action0x60 = NULL;
}

// FUNCTION: LEGO1 0x100c1290
// FUNCTION: BETA10 0x1014e354
MxStreamController::~MxStreamController()
{
	MxTrace("Destroy %s controller.\n", m_atom.GetInternal());
	AUTOLOCK(m_criticalSection);

	MxDSSubscriber* subscriber;
	while (m_subscriberList.PopFront(subscriber)) {
		delete subscriber;
	}

	MxDSObject* action;
	while (m_unk0x3c.PopFront(action)) {
		delete action;
	}

	if (m_provider) {
		MxStreamProvider* provider = m_provider;
		m_provider = NULL;
#ifdef COMPAT_MODE
		{
			MxDSAction action;
			provider->VTable0x20(&action);
		}
#else
		provider->VTable0x20(&MxDSAction());
#endif
		delete provider;
	}

	if (m_unk0x2c) {
		delete m_unk0x2c;
		m_unk0x2c = NULL;
	}

	while (m_unk0x54.PopFront(action)) {
		delete action;
	}
}

// FUNCTION: LEGO1 0x100c1520
MxResult MxStreamController::Open(const char* p_filename)
{
	char sourceName[256];
	AUTOLOCK(m_criticalSection);

	MakeSourceName(sourceName, p_filename);
	this->m_atom = MxAtomId(sourceName, e_lowerCase2);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c15d0
void MxStreamController::AddSubscriber(MxDSSubscriber* p_subscriber)
{
	m_subscriberList.push_back(p_subscriber);
}

// FUNCTION: LEGO1 0x100c1620
void MxStreamController::RemoveSubscriber(MxDSSubscriber* p_subscriber)
{
	m_subscriberList.remove(p_subscriber);
}

// FUNCTION: LEGO1 0x100c1690
MxResult MxStreamController::VTable0x20(MxDSAction* p_action)
{
	AUTOLOCK(m_criticalSection);

	MxResult result;
	MxU32 offset = 0;

	MxS32 objectId = p_action->GetObjectId();
	MxStreamProvider* provider = m_provider;

	if ((MxS32) provider->GetLengthInDWords() > objectId) {
		offset = provider->GetBufferForDWords()[objectId];
	}

	if (offset) {
		result = VTable0x2c(p_action, offset);
	}
	else {
		result = FAILURE;
	}

	return result;
}

// FUNCTION: LEGO1 0x100c1740
MxResult MxStreamController::VTable0x24(MxDSAction* p_action)
{
	AUTOLOCK(m_criticalSection);
	VTable0x30(p_action);
	m_action0x60 = (MxDSAction*) m_unk0x54.FindAndErase(p_action);
	if (m_action0x60 == NULL) {
		return FAILURE;
	}
	else {
		p_action->SetUnknown24(m_action0x60->GetUnknown24());
		p_action->SetObjectId(m_action0x60->GetObjectId());
		return FUN_100c1f00(m_action0x60);
	}
}

// FUNCTION: LEGO1 0x100c1800
MxResult MxStreamController::FUN_100c1800(MxDSAction* p_action, MxU32 p_val)
{
	MxNextActionDataStart* dataActionStart =
		new MxNextActionDataStart(p_action->GetObjectId(), p_action->GetUnknown24(), p_val);
	if (dataActionStart == NULL) {
		return FAILURE;
	}

	m_nextActionList.push_back(dataActionStart);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c1a00
MxResult MxStreamController::FUN_100c1a00(MxDSAction* p_action, MxU32 p_offset)
{
	if (p_action->GetUnknown24() == -1) {
		MxS16 newUnknown24 = -1;

		// These loops might be a template function in the list classes
		for (MxDSObjectList::iterator it = m_unk0x54.begin(); it != m_unk0x54.end(); it++) {
			MxDSObject* action = *it;

			if (action->GetObjectId() == p_action->GetObjectId()) {
				newUnknown24 = Max(newUnknown24, action->GetUnknown24());
			}
		}

		if (newUnknown24 == -1) {
			for (MxDSObjectList::iterator it = m_unk0x3c.begin(); it != m_unk0x3c.end(); it++) {
				MxDSObject* action = *it;

				if (action->GetObjectId() == p_action->GetObjectId()) {
					newUnknown24 = Max(newUnknown24, action->GetUnknown24());
				}
			}

			if (newUnknown24 == -1) {
				for (MxDSSubscriberList::iterator it = m_subscriberList.begin(); it != m_subscriberList.end(); it++) {
					MxDSSubscriber* subscriber = *it;

					if (subscriber->GetObjectId() == p_action->GetObjectId()) {
						newUnknown24 = Max(newUnknown24, subscriber->GetUnknown48());
					}
				}
			}
		}

		p_action->SetUnknown24(newUnknown24 + 1);
	}
	else {
		if (m_unk0x3c.Find(p_action)) {
			return FAILURE;
		}
	}

	MxDSStreamingAction* streamingAction = new MxDSStreamingAction(*p_action, p_offset);

	if (!streamingAction) {
		return FAILURE;
	}

	MxU32 fileSize = m_provider->GetFileSize();
	streamingAction->SetBufferOffset(fileSize * (p_offset / fileSize));
	streamingAction->SetObjectId(p_action->GetObjectId());

	MxLong time = Timer()->GetTime();
	streamingAction->SetUnknown90(time);

	m_unk0x3c.push_back(streamingAction);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c1c10
MxResult MxStreamController::VTable0x2c(MxDSAction* p_action, MxU32 p_bufferval)
{
	AUTOLOCK(m_criticalSection);
	if (FUN_100c1a00(p_action, p_bufferval) != SUCCESS) {
		return FAILURE;
	}
	return FUN_100c1800(p_action, (p_bufferval / m_provider->GetFileSize()) * m_provider->GetFileSize());
}

// FUNCTION: LEGO1 0x100c1ce0
MxResult MxStreamController::VTable0x30(MxDSAction* p_action)
{
	AUTOLOCK(m_criticalSection);
	MxResult result = FAILURE;
	MxDSObject* action = m_unk0x3c.FindAndErase(p_action);
	if (action != NULL) {
		MxNextActionDataStart* data = m_nextActionList.FindAndErase(action->GetObjectId(), action->GetUnknown24());
		delete action;
		delete data;
		result = SUCCESS;
	}
	return result;
}

// FUNCTION: LEGO1 0x100c1da0
MxResult MxStreamController::InsertActionToList54(MxDSAction* p_action)
{
	AUTOLOCK(m_criticalSection);
	MxDSAction* action = p_action->Clone();

	if (action == NULL) {
		return FAILURE;
	}
	else {
		m_unk0x54.push_back(action);
		return SUCCESS;
	}
}

// FUNCTION: LEGO1 0x100c1e70
MxPresenter* MxStreamController::FUN_100c1e70(MxDSAction& p_action)
{
	AUTOLOCK(m_criticalSection);
	MxPresenter* result = NULL;
	if (p_action.GetObjectId() != -1) {
		MxDSObject* action = m_unk0x3c.Find(&p_action);
		if (action != NULL) {
			result = action->GetUnknown28();
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100c1f00
MxResult MxStreamController::FUN_100c1f00(MxDSAction* p_action)
{
	AUTOLOCK(m_criticalSection);

	MxU32 objectId = p_action->GetObjectId();
	MxStreamChunk* chunk = new MxStreamChunk;

	if (!chunk) {
		return FAILURE;
	}

	chunk->SetChunkFlags(DS_CHUNK_BIT3);
	chunk->SetObjectId(objectId);

	if (chunk->SendChunk(m_subscriberList, FALSE, p_action->GetUnknown24()) != SUCCESS) {
		delete chunk;
	}

	if (p_action->IsA("MxDSMultiAction")) {
		MxDSActionList* actions = ((MxDSMultiAction*) p_action)->GetActionList();
		MxDSActionListCursor cursor(actions);
		MxDSAction* action;

		while (cursor.Next(action)) {
			if (FUN_100c1f00(action) != SUCCESS) {
				return FAILURE;
			}
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c20b0
MxNextActionDataStart* MxStreamController::FindNextActionDataStartFromStreamingAction(MxDSStreamingAction* p_action)
{
	return m_nextActionList.Find(p_action->GetObjectId(), p_action->GetUnknown24());
}

// FUNCTION: LEGO1 0x100c20d0
// FUNCTION: BETA10 0x1014f3b5
MxBool MxStreamController::IsStoped(MxDSObject* p_obj)
{
	MxDSSubscriber* subscriber = m_subscriberList.Find(p_obj);

	if (subscriber) {
		MxTrace(
			"Subscriber for action (stream %d, instance %d) from %s is still here.\n",
			subscriber->GetObjectId(),
			subscriber->GetUnknown48(),
			GetAtom().GetInternal()
		);
		return FALSE;
	}

	if (p_obj->IsA("MxDSMultiAction")) {
		MxDSActionListCursor cursor(((MxDSMultiAction*) p_obj)->GetActionList());
		MxDSAction* action;

		while (cursor.Next(action)) {
			if (!IsStoped(action)) {
				return FALSE;
			}
		}
	}

	return TRUE;
}

// FUNCTION: LEGO1 0x100c21e0
// FUNCTION: BETA10 0x1014f4e6
MxNextActionDataStart* MxNextActionDataStartList::Find(MxU32 p_id, MxS16 p_value)
{
	for (iterator it = begin(); it != end(); it++) {
		if (p_id == (*it)->GetObjectId() && p_value == (*it)->GetUnknown24()) {
			return *it;
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x100c2240
// FUNCTION: BETA10 0x1014f58c
MxNextActionDataStart* MxNextActionDataStartList::FindAndErase(MxU32 p_id, MxS16 p_value)
{
	MxNextActionDataStart* match = NULL;

	for (iterator it = begin(); it != end(); it++) {
		if (p_id == (*it)->GetObjectId() && (p_value == -2 || p_value == (*it)->GetUnknown24())) {
			match = *it;
			erase(it);
			break;
		}
	}

	return match;
}
