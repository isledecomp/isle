#include "mxramstreamcontroller.h"

#include "mxautolocker.h"
#include "mxramstreamprovider.h"

DECOMP_SIZE_ASSERT(MxRAMStreamController, 0x98);

undefined* __cdecl FUN_100d0d80(MxU32* p_fileSizeBuffer, MxU32 p_fileSize);

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

		FUN_100d0d80(
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

// STUB: LEGO1 0x100c6210
MxResult MxRAMStreamController::VTable0x20(MxDSAction* p_action)
{
	// TODO STUB
	return FAILURE;
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

// STUB: LEGO1 0x100d0d80
undefined* __cdecl FUN_100d0d80(MxU32* p_fileSizeBuffer, MxU32 p_fileSize)
{
	return NULL;
}
