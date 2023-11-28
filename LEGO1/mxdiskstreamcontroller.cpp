#include "mxdiskstreamcontroller.h"

#include "mxautolocker.h"
#include "mxdiskstreamprovider.h"
#include "mxomni.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(MxDiskStreamController, 0xc8);

// FUNCTION: LEGO1 0x100c7120
MxDiskStreamController::MxDiskStreamController()
{
	m_unk8c = 0;
}

// FUNCTION: LEGO1 0x100c7330 SYNTHETIC
// list<MxDSAction *,allocator<MxDSAction *> >::_Buynode

// FUNCTION: LEGO1 0x100c7420 SYNTHETIC
// list<MxDSBuffer *,allocator<MxDSBuffer *> >::~list<MxDSBuffer *,allocator<MxDSBuffer *> >

// FUNCTION: LEGO1 0x100c7490 SYNTHETIC
// list<MxDSBuffer *,allocator<MxDSBuffer *> >::_Buynode

// FUNCTION: LEGO1 0x100c74e0 SYNTHETIC
// List<MxDSBuffer *>::~List<MxDSBuffer *>

// FUNCTION: LEGO1 0x100c7530 STUB
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
MxResult MxDiskStreamController::vtable0x18(undefined4 p_unknown, undefined4 p_unknown2)
{
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c7960
MxResult MxDiskStreamController::vtable0x34(undefined4 p_unknown)
{
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c7ac0 STUB
MxResult MxDiskStreamController::vtable0x28()
{
	// TODO
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c7c00 STUB
MxResult MxDiskStreamController::vtable0x30(undefined4 p_unknown)
{
	// TODO
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c7ff0 STUB
MxResult MxDiskStreamController::vtable0x20(MxDSAction* p_action)
{
	// TODO
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c8160 STUB
MxResult MxDiskStreamController::vtable0x24(undefined4 p_unknown)
{
	// TODO
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c8640 STUB
MxResult MxDiskStreamController::Tickle()
{
	// TODO
	return SUCCESS;
}
