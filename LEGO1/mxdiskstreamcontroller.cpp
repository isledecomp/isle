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

// TEMPLATE: LEGO1 0x100c7330
// list<MxDSAction *,allocator<MxDSAction *> >::_Buynode

// TEMPLATE: LEGO1 0x100c7420
// list<MxDSBuffer *,allocator<MxDSBuffer *> >::~list<MxDSBuffer *,allocator<MxDSBuffer *> >

// TEMPLATE: LEGO1 0x100c7490
// list<MxDSBuffer *,allocator<MxDSBuffer *> >::_Buynode

// TEMPLATE: LEGO1 0x100c74e0
// List<MxDSBuffer *>::~List<MxDSBuffer *>

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
MxResult MxDiskStreamController::vtable0x18(undefined4 p_unknown, undefined4 p_unknown2)
{
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c7960
MxResult MxDiskStreamController::vtable0x34(undefined4 p_unknown)
{
	return FAILURE;
}

// STUB: LEGO1 0x100c7ac0
MxResult MxDiskStreamController::vtable0x28()
{
	// TODO
	return FAILURE;
}

// STUB: LEGO1 0x100c7c00
MxResult MxDiskStreamController::vtable0x30(undefined4 p_unknown)
{
	// TODO
	return FAILURE;
}

// STUB: LEGO1 0x100c7ff0
MxResult MxDiskStreamController::vtable0x20(MxDSAction* p_action)
{
	// TODO
	return FAILURE;
}

// STUB: LEGO1 0x100c8160
MxResult MxDiskStreamController::vtable0x24(undefined4 p_unknown)
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
