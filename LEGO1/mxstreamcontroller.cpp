#include "mxstreamcontroller.h"

#include "legoomni.h"
#include "mxautolocker.h"
#include "mxnextactiondatastart.h"
#include "mxstreamchunk.h"

DECOMP_SIZE_ASSERT(MxStreamController, 0x64)
DECOMP_SIZE_ASSERT(MxNextActionDataStart, 0x14)

// FUNCTION: LEGO1 0x100b9400
MxResult MxStreamController::vtable0x18(undefined4 p_unknown, undefined4 p_unknown2)
{
	return FAILURE;
}

// FUNCTION: LEGO1 0x100b9410
MxResult MxStreamController::vtable0x1C(undefined4 p_unknown, undefined4 p_unknown2)
{
	return FAILURE;
}

// FUNCTION: LEGO1 0x100b9420
MxResult MxStreamController::vtable0x28()
{
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c0b90
MxStreamController::MxStreamController()
{
	m_provider = NULL;
	m_unk2c = 0; // TODO: probably also NULL
	m_action0x60 = NULL;
}

// TEMPLATE: LEGO1 0x100c0d60
// list<MxDSAction *,allocator<MxDSAction *> >::~list<MxDSAction *,allocator<MxDSAction *> >

// TEMPLATE: LEGO1 0x100c0dd0
// list<MxDSSubscriber *,allocator<MxDSSubscriber *> >::~list<MxDSSubscriber *,allocator<MxDSSubscriber *> >

// TEMPLATE: LEGO1 0x100c0e40
// list<MxDSSubscriber *,allocator<MxDSSubscriber *> >::_Buynode

// clang-format off
// TEMPLATE: LEGO1 0x100c0e70
// list<MxNextActionDataStart *,allocator<MxNextActionDataStart *> >::~list<MxNextActionDataStart *,allocator<MxNextActionDataStart *> >
// clang-format on

// TEMPLATE: LEGO1 0x100c0ee0
// list<MxNextActionDataStart *,allocator<MxNextActionDataStart *> >::_Buynode

// TEMPLATE: LEGO1 0x100c0fc0
// MxStreamListMxDSSubscriber::~MxStreamListMxDSSubscriber

// TEMPLATE: LEGO1 0x100c1010
// MxStreamListMxDSAction::~MxStreamListMxDSAction

// TEMPLATE: LEGO1 0x100c1060
// MxStreamListMxNextActionDataStart::~MxStreamListMxNextActionDataStart

// TEMPLATE: LEGO1 0x100c10b0
// MxStreamList<MxDSSubscriber *>::~MxStreamList<MxDSSubscriber *>

// TEMPLATE: LEGO1 0x100c1100
// MxStreamList<MxDSAction *>::~MxStreamList<MxDSAction *>

// TEMPLATE: LEGO1 0x100c1150
// MxStreamList<MxNextActionDataStart *>::~MxStreamList<MxNextActionDataStart *>

// TEMPLATE: LEGO1 0x100c11a0
// List<MxDSSubscriber *>::~List<MxDSSubscriber *>

// TEMPLATE: LEGO1 0x100c11f0
// List<MxDSAction *>::~List<MxDSAction *>

// TEMPLATE: LEGO1 0x100c1240
// List<MxNextActionDataStart *>::~List<MxNextActionDataStart *>

// STUB: LEGO1 0x100c1290
MxStreamController::~MxStreamController()
{
	// TODO
}

// FUNCTION: LEGO1 0x100c1520
MxResult MxStreamController::Open(const char* p_filename)
{
	char sourceName[256];
	MxAutoLocker locker(&m_criticalSection);

	MakeSourceName(sourceName, p_filename);
	this->atom = MxAtomId(sourceName, LookupMode_LowerCase2);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c1690
MxResult MxStreamController::vtable0x20(MxDSAction* p_action)
{
	MxAutoLocker locker(&m_criticalSection);

	MxResult result;
	MxU32 offset = 0;

	MxS32 objectId = p_action->GetObjectId();
	MxStreamProvider* provider = m_provider;

	if ((MxS32) provider->GetLengthInDWords() > objectId)
		offset = provider->GetBufferForDWords()[objectId];

	if (offset)
		result = vtable0x2c(p_action, offset);
	else
		result = FAILURE;

	return result;
}

// STUB: LEGO1 0x100c1740
MxResult MxStreamController::vtable0x24(undefined4 p_unknown)
{
	// TODO STUB
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c1800
MxResult MxStreamController::FUN_100c1800(MxDSAction* p_action, MxU32 p_val)
{
	MxNextActionDataStart* dataActionStart =
		new MxNextActionDataStart(p_action->GetObjectId(), p_action->GetUnknown24(), p_val);
	if (dataActionStart == NULL) {
		return FAILURE;
	}

	m_nextActionList.push_back(dataActionStart);
	return SUCCESS;
}

// STUB: LEGO1 0x100c1a00
MxResult MxStreamController::FUN_100c1a00(MxDSAction* p_action, MxU32 p_bufferval)
{
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c1c10
MxResult MxStreamController::vtable0x2c(MxDSAction* p_action, MxU32 p_bufferval)
{
	MxAutoLocker locker(&m_criticalSection);
	if (FUN_100c1a00(p_action, p_bufferval) != SUCCESS) {
		return FAILURE;
	}
	return FUN_100c1800(p_action, (p_bufferval / m_provider->GetFileSize()) * m_provider->GetFileSize());
}

// STUB: LEGO1 0x100c1ce0
MxResult MxStreamController::vtable0x30(undefined4 p_unknown)
{
	return FAILURE;
}

// STUB: LEGO1 0x100c20d0
MxBool MxStreamController::FUN_100c20d0(MxDSObject& p_obj)
{
	// TODO
	return TRUE;
}
