#include "mxramstreamcontroller.h"

#include "mxautolocker.h"
#include "mxramstreamprovider.h"

DECOMP_SIZE_ASSERT(MxRAMStreamController, 0x98);

undefined* __cdecl FUN_100d0d80(MxU32* p_fileSizeBuffer, MxU32 p_fileSize)
{
	return NULL;
}

// OFFSET: LEGO1 0x100c6110
MxResult MxRAMStreamController::Open(const char* p_filename)
{
	MxResult result = FAILURE;
	MxAutoLocker locker(&m_criticalSection);
	if (MxStreamController::Open(p_filename) == 0) {
		MxRAMStreamProvider* provider = new MxRAMStreamProvider();
		m_provider = provider;
		if (provider != NULL) {
			if (m_provider->SetResourceToGet(this) == SUCCESS) {
				FUN_100d0d80(provider->GetBufferOfFileSize(), provider->GetFileSize());
				// m_buffer todo
				result = SUCCESS;
			}
		}
	}
	return result;
}

// OFFSET: LEGO1 0x100c6210 STUB
MxResult MxRAMStreamController::vtable0x20(MxDSAction* p_action)
{
	// TODO STUB
	return FAILURE;
}

// OFFSET: LEGO1 0x100c6320 STUB
MxResult MxRAMStreamController::vtable0x24(undefined4 p_unknown)
{
	// TODO STUB
	return FAILURE;
}
