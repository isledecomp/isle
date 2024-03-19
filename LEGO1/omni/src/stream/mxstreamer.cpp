#include "mxstreamer.h"

#include "mxdiskstreamcontroller.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxramstreamcontroller.h"

#include <algorithm>

DECOMP_SIZE_ASSERT(MxStreamer, 0x2c);
DECOMP_SIZE_ASSERT(MxMemoryPool64, 0x0c);
DECOMP_SIZE_ASSERT(MxMemoryPool128, 0x0c);
DECOMP_SIZE_ASSERT(MxBitset<22>, 0x04);
DECOMP_SIZE_ASSERT(MxBitset<2>, 0x04);

// FUNCTION: LEGO1 0x100b8f00
MxStreamer::MxStreamer()
{
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x100b9190
MxResult MxStreamer::Create()
{
	if (m_pool64.Allocate() || m_pool128.Allocate()) {
		return FAILURE;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100b91d0
MxStreamer::~MxStreamer()
{
	while (!m_openStreams.empty()) {
		MxStreamController* c = m_openStreams.front();
		m_openStreams.pop_front();
		delete c;
	}

	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x100b92c0
MxStreamController* MxStreamer::Open(const char* p_name, MxU16 p_lookupType)
{
	MxStreamController* stream = NULL;

	if (!GetOpenStream(p_name)) {
		switch (p_lookupType) {
		case e_diskStream:
			stream = new MxDiskStreamController();
			break;
		case e_RAMStream:
			stream = new MxRAMStreamController();
			break;
		}

		if (stream && (stream->Open(p_name) != SUCCESS || AddStreamControllerToOpenList(stream) != SUCCESS)) {
			delete stream;
			stream = NULL;
		}
	}

	return stream;
}

// FUNCTION: LEGO1 0x100b9570
MxLong MxStreamer::Close(const char* p_name)
{
	MxDSAction ds;
	ds.SetUnknown24(-2);

	for (list<MxStreamController*>::iterator it = m_openStreams.begin(); it != m_openStreams.end(); it++) {
		MxStreamController* c = *it;

		if (!p_name || !strcmp(p_name, c->GetAtom().GetInternal())) {
			m_openStreams.erase(it);

			if (c->FUN_100c20d0(ds)) {
				delete c;
			}
			else {
#ifdef COMPAT_MODE
				{
					MxStreamerNotification notification(c_notificationStreamer, NULL, c);
					NotificationManager()->Send(this, &notification);
				}
#else
				NotificationManager()->Send(this, &MxStreamerNotification(c_notificationStreamer, NULL, c));
#endif
			}

			return SUCCESS;
		}
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x100b9700
MxNotificationParam* MxStreamerNotification::Clone()
{
	return new MxStreamerNotification(m_type, m_sender, m_controller);
}

// FUNCTION: LEGO1 0x100b9870
MxStreamController* MxStreamer::GetOpenStream(const char* p_name)
{
	for (list<MxStreamController*>::iterator it = m_openStreams.begin(); it != m_openStreams.end(); it++) {
		MxStreamController* c = *it;
		MxAtomId& atom = c->GetAtom();
		if (p_name) {
			if (!strcmp(atom.GetInternal(), p_name)) {
				return *it;
			}
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
MxResult MxStreamer::AddStreamControllerToOpenList(MxStreamController* p_stream)
{
	if (find(m_openStreams.begin(), m_openStreams.end(), p_stream) == m_openStreams.end()) {
		m_openStreams.push_back(p_stream);
		return SUCCESS;
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x100b99b0
MxResult MxStreamer::FUN_100b99b0(MxDSAction* p_action)
{
	MxStreamController* controller;
	if (p_action != NULL && p_action->GetAtomId().GetInternal() != NULL && p_action->GetObjectId() != -1) {
		controller = GetOpenStream(p_action->GetAtomId().GetInternal());
		if (controller == NULL) {
			return FAILURE;
		}
		return controller->VTable0x20(p_action);
	}
	return FAILURE;
}

// FUNCTION: LEGO1 0x100b99f0
MxResult MxStreamer::DeleteObject(MxDSAction* p_dsAction)
{
	MxDSAction tempAction;

	if (p_dsAction == NULL) {
		tempAction.SetUnknown24(-2);
	}
	else {
		tempAction.SetObjectId(p_dsAction->GetObjectId());
		tempAction.SetAtomId(p_dsAction->GetAtomId());
		tempAction.SetUnknown24(p_dsAction->GetUnknown24());
	}

	MxResult result = FAILURE;
	for (list<MxStreamController*>::iterator it = m_openStreams.begin(); it != m_openStreams.end(); it++) {
		const char* id = p_dsAction->GetAtomId().GetInternal();
		if (!id || id == (*it)->GetAtom().GetInternal()) {
			tempAction.SetAtomId((*it)->GetAtom());
			result = (*it)->VTable0x24(&tempAction);
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100b9b30
MxBool MxStreamer::FUN_100b9b30(MxDSObject& p_dsObject)
{
	MxStreamController* controller = GetOpenStream(p_dsObject.GetAtomId().GetInternal());
	if (controller) {
		return controller->FUN_100c20d0(p_dsObject);
	}
	return TRUE;
}

// FUNCTION: LEGO1 0x100b9b60
MxLong MxStreamer::Notify(MxParam& p_param)
{
	if (((MxNotificationParam&) p_param).GetNotification() == c_notificationStreamer) {
		MxDSAction ds;

		ds.SetUnknown24(-2);

		MxStreamController* c = static_cast<MxStreamerNotification&>(p_param).GetController();

		if (c->FUN_100c20d0(ds)) {
			delete c;
		}
		else {
#ifdef COMPAT_MODE
			{
				MxStreamerNotification notification(c_notificationStreamer, NULL, c);
				NotificationManager()->Send(this, &notification);
			}
#else
			NotificationManager()->Send(this, &MxStreamerNotification(c_notificationStreamer, NULL, c));
#endif
		}
	}

	return 0;
}
