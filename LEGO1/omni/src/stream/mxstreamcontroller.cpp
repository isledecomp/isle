#include "mxstreamcontroller.h"

#include "mxautolocker.h"
#include "mxdsmultiaction.h"
#include "mxdsstreamingaction.h"
#include "mxnextactiondatastart.h"
#include "mxomni.h"
#include "mxstl/stlcompat.h"
#include "mxstreamchunk.h"
#include "mxtimer.h"
#include "mxutil.h"

DECOMP_SIZE_ASSERT(MxStreamController, 0x64)
DECOMP_SIZE_ASSERT(MxNextActionDataStart, 0x14)

// FUNCTION: LEGO1 0x100b9400
MxResult MxStreamController::VTable0x18(undefined4, undefined4)
{
	return FAILURE;
}

// FUNCTION: LEGO1 0x100b9410
MxResult MxStreamController::VTable0x1c(undefined4, undefined4)
{
	return FAILURE;
}

// FUNCTION: LEGO1 0x100b9420
MxDSStreamingAction* MxStreamController::VTable0x28()
{
	return NULL;
}

// FUNCTION: LEGO1 0x100c0b90
MxStreamController::MxStreamController()
{
	m_provider = NULL;
	m_unk0x2c = NULL;
	m_action0x60 = NULL;
}

// FUNCTION: LEGO1 0x100c1290
MxStreamController::~MxStreamController()
{
	MxAutoLocker lock(&m_criticalSection);

	MxDSSubscriber* subscriber;
	while (m_subscriberList.PopFront(subscriber))
		delete subscriber;

	MxDSAction* action;
	while (m_unk0x3c.PopFront(action))
		delete action;

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

	while (m_unk0x54.PopFront(action))
		delete action;
}

// FUNCTION: LEGO1 0x100c1520
MxResult MxStreamController::Open(const char* p_filename)
{
	char sourceName[256];
	MxAutoLocker lock(&m_criticalSection);

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
	MxAutoLocker lock(&m_criticalSection);

	MxResult result;
	MxU32 offset = 0;

	MxS32 objectId = p_action->GetObjectId();
	MxStreamProvider* provider = m_provider;

	if ((MxS32) provider->GetLengthInDWords() > objectId)
		offset = provider->GetBufferForDWords()[objectId];

	if (offset)
		result = VTable0x2c(p_action, offset);
	else
		result = FAILURE;

	return result;
}

// FUNCTION: LEGO1 0x100c1740
MxResult MxStreamController::VTable0x24(MxDSAction* p_action)
{
	MxAutoLocker lock(&m_criticalSection);
	VTable0x30(p_action);
	m_action0x60 = m_unk0x54.Find(p_action, TRUE);
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
		for (MxStreamListMxDSAction::iterator it = m_unk0x54.begin(); it != m_unk0x54.end(); it++) {
			MxDSAction* action = *it;

			if (action->GetObjectId() == p_action->GetObjectId())
				newUnknown24 = Max(newUnknown24, action->GetUnknown24());
		}

		if (newUnknown24 == -1) {
			for (MxStreamListMxDSAction::iterator it = m_unk0x3c.begin(); it != m_unk0x3c.end(); it++) {
				MxDSAction* action = *it;

				if (action->GetObjectId() == p_action->GetObjectId())
					newUnknown24 = Max(newUnknown24, action->GetUnknown24());
			}

			if (newUnknown24 == -1) {
				for (MxStreamListMxDSSubscriber::iterator it = m_subscriberList.begin(); it != m_subscriberList.end();
					 it++) {
					MxDSSubscriber* subscriber = *it;

					if (subscriber->GetObjectId() == p_action->GetObjectId())
						newUnknown24 = Max(newUnknown24, subscriber->GetUnknown48());
				}
			}
		}

		p_action->SetUnknown24(newUnknown24 + 1);
	}
	else {
		if (m_unk0x3c.Find(p_action, FALSE))
			return FAILURE;
	}

	MxDSStreamingAction* streamingAction = new MxDSStreamingAction(*p_action, p_offset);

	if (!streamingAction)
		return FAILURE;

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
	MxAutoLocker lock(&m_criticalSection);
	if (FUN_100c1a00(p_action, p_bufferval) != SUCCESS) {
		return FAILURE;
	}
	return FUN_100c1800(p_action, (p_bufferval / m_provider->GetFileSize()) * m_provider->GetFileSize());
}

// FUNCTION: LEGO1 0x100c1ce0
MxResult MxStreamController::VTable0x30(MxDSAction* p_action)
{
	MxAutoLocker lock(&m_criticalSection);
	MxResult result = FAILURE;
	MxDSAction* action = m_unk0x3c.Find(p_action, TRUE);
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
	MxAutoLocker lock(&m_criticalSection);
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
	MxAutoLocker lock(&m_criticalSection);
	MxPresenter* result = NULL;
	if (p_action.GetObjectId() != -1) {
		MxDSAction* action = m_unk0x3c.Find(&p_action, FALSE);
		if (action != NULL) {
			result = action->GetUnknown28();
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100c1f00
MxResult MxStreamController::FUN_100c1f00(MxDSAction* p_action)
{
	MxAutoLocker lock(&m_criticalSection);

	MxU32 objectId = p_action->GetObjectId();
	MxStreamChunk* chunk = new MxStreamChunk;

	if (!chunk)
		return FAILURE;

	chunk->SetFlags(MxDSChunk::c_bit3);
	chunk->SetObjectId(objectId);

	if (chunk->SendChunk(m_subscriberList, FALSE, p_action->GetUnknown24()) != SUCCESS)
		delete chunk;

	if (p_action->IsA("MxDSMultiAction")) {
		MxDSActionList* actions = ((MxDSMultiAction*) p_action)->GetActionList();
		MxDSActionListCursor cursor(actions);
		MxDSAction* action;

		while (cursor.Next(action)) {
			if (FUN_100c1f00(action) != SUCCESS)
				return FAILURE;
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
MxBool MxStreamController::FUN_100c20d0(MxDSObject& p_obj)
{
	if (m_subscriberList.Find(&p_obj))
		return FALSE;

	if (p_obj.IsA("MxDSMultiAction")) {
		MxDSActionList* actions = ((MxDSMultiAction&) p_obj).GetActionList();
		MxDSActionListCursor cursor(actions);
		MxDSAction* action;

		while (cursor.Next(action)) {
			if (!FUN_100c20d0(*action))
				return FALSE;
		}
	}

	return TRUE;
}
