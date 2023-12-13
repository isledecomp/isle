#include "mxdiskstreamcontroller.h"

#include "mxautolocker.h"
#include "mxdiskstreamprovider.h"
#include "mxdsstreamingaction.h"
#include "mxomni.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(MxDiskStreamController, 0xc8);

// FUNCTION: LEGO1 0x100c7120
MxDiskStreamController::MxDiskStreamController()
{
	m_unk0x8c = 0;
}

// STUB: LEGO1 0x100c7530
MxDiskStreamController::~MxDiskStreamController()
{
	// TODO
}

// FUNCTION: LEGO1 0x100c7790
MxResult MxDiskStreamController::Open(const char* p_filename)
{
	MxAutoLocker lock(&this->m_criticalSection);
	MxResult result = MxStreamController::Open(p_filename);

	if (result == SUCCESS) {
		m_provider = new MxDiskStreamProvider();
		if (m_provider == NULL) {
			result = FAILURE;
		}
		else {
			result = m_provider->SetResourceToGet(this);
			if (result != SUCCESS) {
				delete m_provider;
				m_provider = NULL;
			}
			else {
				TickleManager()->RegisterClient(this, 10);
			}
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100c7880
MxResult MxDiskStreamController::VTable0x18(undefined4, undefined4)
{
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c7960
MxResult MxDiskStreamController::VTable0x34(undefined4)
{
	return FAILURE;
}

// STUB: LEGO1 0x100c7ac0
MxResult MxDiskStreamController::VTable0x28()
{
	// TODO
	return FAILURE;
}

// STUB: LEGO1 0x100c7c00
MxResult MxDiskStreamController::VTable0x30(MxDSAction* p_action)
{
	// TODO
	return FAILURE;
}

// STUB: LEGO1 0x100c7f4
void MxDiskStreamController::FUN_100c7f4(MxDSStreamingAction* p_streamingaction)
{
	// TODO
	// seems to do something with a list
}

// FUNCTION: LEGO1 0x100c7ff0
MxResult MxDiskStreamController::VTable0x20(MxDSAction* p_action)
{
	MxAutoLocker lock(&this->m_criticalSection);
	MxResult result;
	MxDSStreamingAction* entry = (MxDSStreamingAction*)m_list0x80.Find(p_action, FALSE); // TODO: is this a seperate class?
	if (!entry) {
		result = MxStreamController::VTable0x20((MxDSAction*)p_action);
	}
	else {
		MxDSStreamingAction* action = new MxDSStreamingAction(*p_action, 0);
		action->SetUnknown84(entry->GetUnknown84());
		action->SetUnknown8c(entry->GetUnknown8c());
		action->SetUnknowna0(entry->GetUnknowna0());

		FUN_100c7f4(action);
		result = vtable0x2c(p_action, action->GetBufferOffset());
	}

	if (result == SUCCESS)
	{
		m_unk70 = 1;
		m_unkc4 = 1;
	}
	return result;
}

// STUB: LEGO1 0x100c8160
MxResult MxDiskStreamController::VTable0x24(MxDSAction* p_action)
{
	// TODO
	return FAILURE;
}

// STUB: LEGO1 0x100c8640
MxResult MxDiskStreamController::Tickle()
{
	// TODO
	return SUCCESS;
}
