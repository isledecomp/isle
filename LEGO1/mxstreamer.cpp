#include "mxstreamer.h"

#include "legoomni.h"
#include "mxdiskstreamcontroller.h"
#include "mxnotificationmanager.h"
#include "mxramstreamcontroller.h"

#include <algorithm>

DECOMP_SIZE_ASSERT(MxStreamer, 0x2c);

// FUNCTION: LEGO1 0x100b8f00
MxStreamer::MxStreamer()
{
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x100b9190
MxResult MxStreamer::Create()
{
	undefined* b = new undefined[m_subclass1.GetSize() * 0x5800];
	m_subclass1.SetBuffer(b);
	if (b) {
		b = new undefined[m_subclass2.GetSize() * 0x800];
		m_subclass2.SetBuffer(b);
		if (b) {
			return SUCCESS;
		}
	}

	return FAILURE;
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
	// TODO
	MxStreamController* stream = NULL;

	if (!GetOpenStream(p_name)) {
		switch (p_lookupType) {
		case e_DiskStream:
			stream = new MxDiskStreamController();
			break;
		case e_RAMStream:
			stream = new MxRAMStreamController();
			break;
		}

		if (!stream || stream->Open(p_name) != SUCCESS || AddStreamControllerToOpenList(stream) != SUCCESS) {
			delete stream;
			stream = NULL;
		}
	}

	return stream;
}

// FUNCTION: LEGO1 0x100b9570
MxLong MxStreamer::Close(const char* p)
{
	MxDSAction ds;

	ds.SetUnknown24(-2);

	for (list<MxStreamController*>::iterator it = m_openStreams.begin(); it != m_openStreams.end(); it++) {
		MxStreamController* c = *it;

		if (!p || !strcmp(p, c->GetAtom().GetInternal())) {
			m_openStreams.erase(it);

			if (!c->FUN_100c20d0(ds)) {
				MxStreamerNotification notif(MXSTREAMER_DELETE_NOTIFY, NULL, c);

				NotificationManager()->Send(this, &notif);
			}
			else {
				delete c;
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

// FUNCTION: LEGO1 0x100b9930
MxResult MxStreamer::AddStreamControllerToOpenList(MxStreamController* stream)
{
	if (find(m_openStreams.begin(), m_openStreams.end(), stream) == m_openStreams.end()) {
		m_openStreams.push_back(stream);
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
		return controller->vtable0x20(p_action);
	}
	return FAILURE;
}

// FUNCTION: LEGO1 0x100b9b30
MxBool MxStreamer::FUN_100b9b30(MxDSObject& p_dsObject)
{
	MxStreamController* controller = GetOpenStream(p_dsObject.GetAtomId().GetInternal());
	if (controller)
		return controller->FUN_100c20d0(p_dsObject);
	return TRUE;
}

// FUNCTION: LEGO1 0x100b9b60
MxLong MxStreamer::Notify(MxParam& p_param)
{
	if (((MxNotificationParam&) p_param).GetNotification() == MXSTREAMER_DELETE_NOTIFY) {
		MxDSAction ds;

		ds.SetUnknown24(-2);

		MxStreamController* c = static_cast<MxStreamerNotification&>(p_param).GetController();

		if (!c->FUN_100c20d0(ds)) {
			MxStreamerNotification notif(MXSTREAMER_DELETE_NOTIFY, NULL, c);
			NotificationManager()->Send(this, &notif);
		}
		else {
			delete c;
		}
	}

	return 0;
}

// No offset, function is always inlined
MxStreamerSubClass1::MxStreamerSubClass1(undefined4 size)
{
	m_buffer = NULL;
	m_size = size;
	undefined4* ptr = &m_unk08;
	for (int i = 0; i >= 0; i--) {
		ptr[i] = 0;
	}
}
