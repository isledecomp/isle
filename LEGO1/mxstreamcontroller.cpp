#include "mxstreamcontroller.h"

#include "legoomni.h"
#include "mxautolocker.h"
#include "mxdsstreamingaction.h"
#include "mxnextactiondatastart.h"
#include "mxstreamchunk.h"

DECOMP_SIZE_ASSERT(MxStreamController, 0x64)
DECOMP_SIZE_ASSERT(MxNextActionDataStart, 0x14)

// FUNCTION: LEGO1 0x100b9400
MxResult MxStreamController::VTable0x18(undefined4, undefined4)
{
	OutputDebugStringA("MxStreamController::VTable0x18 not implemented\n");
	return FAILURE;
}

// FUNCTION: LEGO1 0x100b9410
MxResult MxStreamController::VTable0x1c(undefined4, undefined4)
{
	OutputDebugStringA("MxStreamController::VTable0x1c not implemented\n");
	return FAILURE;
}

// FUNCTION: LEGO1 0x100b9420
MxDSStreamingAction* MxStreamController::VTable0x28()
{
	return NULL;
}

// FUNCTION: LEGO1 0x100c0b90
MxStreamController::MxStreamController()
{
	m_provider = NULL;
	m_unk0x2c = 0; // TODO: probably also NULL
	m_action0x60 = NULL;
}

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
	this->m_atom = MxAtomId(sourceName, LookupMode_LowerCase2);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c1690
MxResult MxStreamController::VTable0x20(MxDSAction* p_action)
{
	MxAutoLocker locker(&m_criticalSection);

	MxResult result;
	MxU32 offset = 0;

	MxS32 objectId = p_action->GetObjectId();
	MxStreamProvider* provider = m_provider;

	if ((MxS32) provider->GetLengthInDWords() > objectId)
		offset = provider->GetBufferForDWords()[objectId];

	if (offset)
		result = VTable0x2c(p_action, offset);
	else
		result = FAILURE;

	return result;
}

// FUNCTION: LEGO1 0x100c1740
MxResult MxStreamController::VTable0x24(MxDSAction* p_action)
{
	MxAutoLocker locker(&m_criticalSection);
	VTable0x30(p_action);
	m_action0x60 = m_unk0x54.Find(p_action, TRUE);
	if (m_action0x60 == NULL) {
		return FAILURE;
	}
	else {
		p_action->SetUnknown24(m_action0x60->GetUnknown24());
		p_action->SetObjectId(m_action0x60->GetObjectId());
		return FUN_100c1f00(m_action0x60);
	}
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
	OutputDebugStringA("MxStreamController::FUN_100c1a00 not implemented\n");
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c1c10
MxResult MxStreamController::VTable0x2c(MxDSAction* p_action, MxU32 p_bufferval)
{
	MxAutoLocker locker(&m_criticalSection);
	if (FUN_100c1a00(p_action, p_bufferval) != SUCCESS) {
		return FAILURE;
	}
	return FUN_100c1800(p_action, (p_bufferval / m_provider->GetFileSize()) * m_provider->GetFileSize());
}

// FUNCTION: LEGO1 0x100c1ce0
MxResult MxStreamController::VTable0x30(MxDSAction* p_action)
{
	MxAutoLocker locker(&m_criticalSection);
	MxResult result = FAILURE;
	MxDSAction* action = m_unk0x3c.Find(p_action, TRUE);
	if (action != NULL) {
		MxNextActionDataStart* data = m_nextActionList.Find(action->GetObjectId(), action->GetUnknown24());
		delete action;
		delete data;
		result = SUCCESS;
	}
	return result;
}

// FUNCTION: LEGO1 0x100c1da0
MxResult MxStreamController::InsertActionToList54(MxDSAction* p_action)
{
	MxAutoLocker locker(&m_criticalSection);
	MxDSAction* action = p_action->Clone();

	if (action == NULL) {
		return FAILURE;
	}
	else {
		m_unk0x54.push_back(action);
		return SUCCESS;
	}
}

// FUNCTION: LEGO1 0x100c1e70
MxPresenter* MxStreamController::FUN_100c1e70(MxDSAction& p_action)
{
	MxAutoLocker locker(&m_criticalSection);
	MxPresenter* result = NULL;
	if (p_action.GetObjectId() != -1) {
		MxDSAction* action = m_unk0x3c.Find(&p_action, FALSE);
		if (action != NULL) {
			result = action->GetUnknown28();
		}
	}

	return result;
}

// STUB: LEGO1 0x100c1f00
MxResult MxStreamController::FUN_100c1f00(MxDSAction* p_action)
{
	OutputDebugStringA("MxStreamController::FUN_100c1f00 not implemented\n");
	// TODO
	return FAILURE;
}

// STUB: LEGO1 0x100c20d0
MxBool MxStreamController::FUN_100c20d0(MxDSObject& p_obj)
{
	OutputDebugStringA("MxStreamController::FUN_100c20d0 not implemented\n");
	// TODO
	return TRUE;
}
