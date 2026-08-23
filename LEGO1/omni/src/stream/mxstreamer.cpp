#include "mxstreamer.h"

#include "mxdebug.h"
#include "mxdiskstreamcontroller.h"
#include "mxdsaction.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxramstreamcontroller.h"

#include <algorithm>
#include <assert.h>

DECOMP_SIZE_ASSERT(MxStreamer, 0x2c);
DECOMP_SIZE_ASSERT(MxMemoryPool64, 0x0c);
DECOMP_SIZE_ASSERT(MxMemoryPool128, 0x0c);
DECOMP_SIZE_ASSERT(MxBitset<22>, 0x04);
DECOMP_SIZE_ASSERT(MxBitset<2>, 0x04);

// FUNCTION: LEGO1 0x100b8f00
// FUNCTION: BETA10 0x10145150
MxStreamer::MxStreamer()
{
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x100b9190
// FUNCTION: BETA10 0x10145220
MxResult MxStreamer::Create()
{
	if (m_pool64.Allocate() || m_pool128.Allocate()) {
		return FAILURE;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100b91d0
// FUNCTION: BETA10 0x10145268
MxStreamer::~MxStreamer()
{
	while (!m_controllers.empty()) {
		MxStreamController* controller = m_controllers.front();

#ifdef COMPAT_MODE
		{
			MxDSAction action;
			assert(controller->IsStoped(&action));
		}
#else
		assert(controller->IsStoped(&MxDSAction()));
#endif

		m_controllers.pop_front();
		delete controller;
	}

	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x100b92c0
// FUNCTION: BETA10 0x1014542d
MxStreamController* MxStreamer::Open(const char* p_name, MxU16 p_lookupType)
{
	MxTrace("Open %s as %s controller\n", p_name, !p_lookupType ? "disk" : "RAM");
	MxTrace("Heap before: %d\n", DebugHeapState());

	MxStreamController* stream = NULL;

	if (GetOpenStream(p_name)) {
		goto done;
	}

	switch (p_lookupType) {
	case e_diskStream:
		stream = new MxDiskStreamController();
		break;
	case e_RAMStream:
		stream = new MxRAMStreamController();
		break;
	}

	if (stream == NULL) {
		goto done;
	}

	if (stream->Open(p_name) != SUCCESS || AddStreamControllerToOpenList(stream) != SUCCESS) {
		delete stream;
		stream = NULL;
	}

done:
	MxTrace("Heap after: %d\n", DebugHeapState());
	return stream;
}

// FUNCTION: LEGO1 0x100b9570
// FUNCTION: BETA10 0x10145638
MxLong MxStreamer::Close(const char* p_name)
{
	MxDSAction ds;
	ds.SetUnknown24(-2);

	for (list<MxStreamController*>::iterator it = m_controllers.begin(); it != m_controllers.end(); it++) {
		MxStreamController* c = *it;

		if (!p_name || c->GetAtom() == p_name) {
			m_controllers.erase(it);

			if (c->IsStoped(&ds)) {
				delete c;
			}
			else {
				NotificationManager()->Send(this, MxStreamerNotification(c_notificationStreamer, NULL, c));
			}

			return SUCCESS;
		}
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x100b9700
// FUNCTION: BETA10 0x10146ed0
MxNotificationParam* MxStreamerNotification::Clone() const
{
	return new MxStreamerNotification(m_type, m_sender, m_controller);
}

// FUNCTION: LEGO1 0x100b9870
// FUNCTION: BETA10 0x1014584b
MxStreamController* MxStreamer::GetOpenStream(const char* p_name)
{
	for (list<MxStreamController*>::iterator it = m_controllers.begin(); it != m_controllers.end(); it++) {
		if ((*it)->GetAtom() == p_name) {
			return *it;
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x100b98f0
void MxStreamer::FUN_100b98f0(MxDSAction* p_action)
{
	MxStreamController* controller = GetOpenStream(p_action->GetAtomId().GetInternal());
	if (controller && controller->IsA("MxDiskStreamController")) {
		((MxDiskStreamController*) controller)->FUN_100c8120(p_action);
	}
}

// FUNCTION: LEGO1 0x100b9930
// FUNCTION: BETA10 0x101458e5
MxResult MxStreamer::AddStreamControllerToOpenList(MxStreamController* p_stream)
{
	list<MxStreamController*>::iterator i = find(m_controllers.begin(), m_controllers.end(), p_stream);

	assert(i == m_controllers.end());

	// DECOMP: Retail is missing the optimization that skips this check if find() reaches the end.
	if (i == m_controllers.end()) {
		m_controllers.push_back(p_stream);
		return SUCCESS;
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x100b99b0
// FUNCTION: BETA10 0x101459ad
MxResult MxStreamer::FUN_100b99b0(MxDSAction* p_action)
{
	// TODO: MxAtomId operator== used here for NULL test. BETA10 0x1007dc20
	if (p_action == NULL || p_action->GetAtomId().GetInternal() == NULL || p_action->GetObjectId() == -1) {
		return FAILURE;
	}

	MxStreamController* controller = GetOpenStream(p_action->GetAtomId().GetInternal());
	if (controller == NULL) {
		return FAILURE;
	}

	return controller->VTable0x20(p_action);
}

// FUNCTION: LEGO1 0x100b99f0
// FUNCTION: BETA10 0x10145a54
MxResult MxStreamer::DeleteObject(MxDSAction* p_dsAction)
{
	MxDSAction tempAction;

	if (p_dsAction) {
		tempAction.SetObjectId(p_dsAction->GetObjectId());
		tempAction.SetAtomId(p_dsAction->GetAtomId());
		tempAction.SetUnknown24(p_dsAction->GetUnknown24());
	}
	else {
		tempAction.SetUnknown24(-2);
	}

	MxResult result = FAILURE;
	for (list<MxStreamController*>::iterator it = m_controllers.begin(); it != m_controllers.end(); it++) {
		// TODO: MxAtomId operator== used here for NULL test. BETA10 0x1007dc20
		if (p_dsAction->GetAtomId().GetInternal() == NULL || p_dsAction->GetAtomId() == (*it)->GetAtom()) {
			tempAction.SetAtomId((*it)->GetAtom());
			result = (*it)->VTable0x24(&tempAction);
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100b9b30
// FUNCTION: BETA10 0x10145d01
MxBool MxStreamer::FUN_100b9b30(MxDSObject& p_dsObject)
{
	MxStreamController* controller = GetOpenStream(p_dsObject.GetAtomId().GetInternal());
	if (controller) {
		return controller->IsStoped(&p_dsObject);
	}
	return TRUE;
}

// FUNCTION: LEGO1 0x100b9b60
// FUNCTION: BETA10 0x10145d51
MxLong MxStreamer::Notify(MxParam& p_param)
{
	MxStreamerNotification& s = static_cast<MxStreamerNotification&>(p_param);

	switch (s.GetNotification()) {
	case c_notificationStreamer: {
		// DECOMP: Beta does not use a variable, but this matches retail better.
		MxStreamController* c = s.GetController();

		MxDSAction ds;
		ds.SetUnknown24(-2);

		if (c->IsStoped(&ds)) {
			delete c;
		}
		else {
			NotificationManager()->Send(this, MxStreamerNotification(c_notificationStreamer, NULL, c));
		}

		break;
	}
	default:
		assert(0);
		break;
	}

	return 0;
}
