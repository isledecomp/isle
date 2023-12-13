#include "mxramstreamcontroller.h"

#include "mxautolocker.h"
#include "mxdsstreamingaction.h"
#include "mxramstreamprovider.h"

DECOMP_SIZE_ASSERT(MxRAMStreamController, 0x98);

undefined* __cdecl ReadData(MxU32* p_fileSizeBuffer, MxU32 p_fileSize);

// FUNCTION: LEGO1 0x100c6110
MxResult MxRAMStreamController::Open(const char* p_filename)
{
	MxAutoLocker locker(&m_criticalSection);
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
	MxAutoLocker locker(&m_criticalSection);
	MxS16 unknown24Value = 0;
	MxResult result = FAILURE;
	if (p_action->GetUnknown24() == -1) {
		p_action->SetUnknown24(-3);
		MxDSAction* action = m_unk0x54.Find(p_action, FALSE);
		if (action != NULL) {
			unknown24Value = action->GetUnknown24() + 1;
		}
		p_action->SetUnknown24(unknown24Value);
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
MxResult MxRAMStreamController::DeserializeObject(MxDSStreamingAction& action)
{
	MxAutoLocker locker(&m_criticalSection);
	MxResult result;
	undefined4 unkVar = 0;
	do {
		m_buffer.FUN_100c6f80(action.GetUnknown94());
		result = m_buffer.FUN_100c67b0(this, &action, &unkVar);
	} while (m_unk0x3c.Find(&action, FALSE) != NULL);
	return result;
}

// STUB: LEGO1 0x100d0d80
undefined* __cdecl ReadData(MxU32* p_fileSizeBuffer, MxU32 p_fileSize)
{
	return NULL;
}
