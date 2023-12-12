#include "mxdsstreamingaction.h"

#include "mxdsbuffer.h"

DECOMP_SIZE_ASSERT(MxDSStreamingAction, 0xb4)

// FUNCTION: LEGO1 0x100cd010
MxDSStreamingAction::MxDSStreamingAction(MxDSAction& p_dsAction, MxU32 p_offset)
{
	Init();

	*this = p_dsAction;
	this->m_unk0x94 = p_offset;
	this->m_bufferOffset = p_offset;
}

// FUNCTION: LEGO1 0x100cd090
MxBool MxDSStreamingAction::HasId(MxU32 p_objectId)
{
	if (this->m_internalAction)
		return this->m_internalAction->HasId(p_objectId);
	return FALSE;
}

// FUNCTION: LEGO1 0x100cd0d0
MxDSStreamingAction::MxDSStreamingAction(MxDSStreamingAction& p_dsStreamingAction)
{
	Init();
	CopyFrom(p_dsStreamingAction);
}

// FUNCTION: LEGO1 0x100cd150
MxDSStreamingAction::~MxDSStreamingAction()
{
	if (this->m_unk0xa0)
		delete this->m_unk0xa0;
	if (this->m_unk0xa4)
		delete this->m_unk0xa4;
	if (this->m_internalAction)
		delete this->m_internalAction;
}

// FUNCTION: LEGO1 0x100cd1e0
MxResult MxDSStreamingAction::Init()
{
	this->m_unk0x94 = 0;
	this->m_bufferOffset = 0;
	this->m_unk0x9c = 0;
	this->m_unk0xa0 = NULL;
	this->m_unk0xa4 = NULL;
	this->m_unk0xa8 = 0;
	this->m_unk0xac = 2;
	this->m_internalAction = NULL;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100cd220
MxDSStreamingAction* MxDSStreamingAction::CopyFrom(MxDSStreamingAction& p_dsStreamingAction)
{
	*this = p_dsStreamingAction;
	this->m_unk0x94 = p_dsStreamingAction.m_unk0x94;
	this->m_bufferOffset = p_dsStreamingAction.m_bufferOffset;
	this->m_unk0x9c = p_dsStreamingAction.m_unk0x9c;
	this->m_unk0xa0 = NULL;
	this->m_unk0xa4 = NULL;
	this->m_unk0xac = p_dsStreamingAction.m_unk0xac;
	this->m_unk0xa8 = p_dsStreamingAction.m_unk0xa8;
	SetInternalAction(p_dsStreamingAction.m_internalAction ? p_dsStreamingAction.m_internalAction->Clone() : NULL);

	return this;
}

// FUNCTION: LEGO1 0x100cd2a0
void MxDSStreamingAction::SetInternalAction(MxDSAction* p_dsAction)
{
	if (this->m_internalAction)
		delete this->m_internalAction;
	this->m_internalAction = p_dsAction;
}

// FUNCTION: LEGO1 0x100cd2d0
void MxDSStreamingAction::FUN_100cd2d0()
{
	if (this->m_duration == -1)
		return;

	MxLong duration = this->m_duration / this->m_loopCount;
	this->m_loopCount--;

	this->m_duration -= duration;
	this->m_unk0xa8 += duration;
}
