#include "mxramstreamcontroller.h"

#include "mxautolock.h"
#include "mxdsstreamingaction.h"
#include "mxramstreamprovider.h"

DECOMP_SIZE_ASSERT(MxRAMStreamController, 0x98);

// FUNCTION: LEGO1 0x100c6110
MxResult MxRAMStreamController::Open(const char* p_filename)
{
	AUTOLOCK(m_criticalSection);
	if (MxStreamController::Open(p_filename) != SUCCESS) {
		return FAILURE;
	}

	m_provider = new MxRAMStreamProvider();
	if (((MxRAMStreamProvider*) m_provider) != NULL) {
		if (m_provider->SetResourceToGet(this) != SUCCESS) {
			return FAILURE;
		}

		ReadData(
			((MxRAMStreamProvider*) m_provider)->GetBufferOfFileSize(),
			((MxRAMStreamProvider*) m_provider)->GetFileSize()
		);
		m_buffer.SetBufferPointer(
			((MxRAMStreamProvider*) m_provider)->GetBufferOfFileSize(),
			((MxRAMStreamProvider*) m_provider)->GetFileSize()
		);
		return SUCCESS;
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x100c6210
MxResult MxRAMStreamController::VTable0x20(MxDSAction* p_action)
{
	AUTOLOCK(m_criticalSection);
	MxS32 unk0x24 = 0;
	MxResult result = FAILURE;

	if (p_action->GetUnknown24() == -1) {
		p_action->SetUnknown24(-3);
		MxDSAction* action = m_unk0x54.Find(p_action, FALSE);
		if (action != NULL) {
			unk0x24 = action->GetUnknown24() + 1;
		}
		p_action->SetUnknown24(unk0x24);
	}
	else {
		if (m_unk0x54.Find(p_action, FALSE)) {
			return FAILURE;
		}
	}

	if (MxStreamController::VTable0x20(p_action) == SUCCESS) {
		MxDSStreamingAction* action = (MxDSStreamingAction*) m_unk0x3c.Find(p_action, FALSE);
		MxDSStreamingAction streamingaction(*action);
		result = DeserializeObject(streamingaction);
	}
	return result;
}

// FUNCTION: LEGO1 0x100c6320
MxResult MxRAMStreamController::VTable0x24(MxDSAction* p_action)
{
	MxDSAction action;
	do {
		if (m_action0x60 != NULL) {
			delete m_action0x60;
			m_action0x60 = NULL;
		}
		action = *p_action;
		MxStreamController::VTable0x24(&action);
	} while (m_action0x60 != NULL);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c63c0
MxResult MxRAMStreamController::DeserializeObject(MxDSStreamingAction& p_action)
{
	AUTOLOCK(m_criticalSection);
	MxResult result;
	MxDSStreamingAction* value = NULL;

	do {
		m_buffer.FUN_100c6f80(p_action.GetUnknown94());
		// Probably not MxResult, see below
		result = m_buffer.FUN_100c67b0(this, &p_action, &value);
	} while (m_unk0x3c.Find(&p_action, FALSE) != NULL);

	return result == SUCCESS ? SUCCESS : FAILURE;
}
