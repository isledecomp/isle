#include "mxdsstreamingaction.h"

#include "mxdsbuffer.h"

DECOMP_SIZE_ASSERT(MxDSStreamingAction, 0xb4)

// FUNCTION: LEGO1 0x100cd010
// FUNCTION: BETA10 0x1015f380
MxDSStreamingAction::MxDSStreamingAction(MxDSAction& p_dsAction, MxU32 p_offset)
{
	Init();

	MxDSAction::operator=(p_dsAction);
	m_unk0x94 = p_offset;
	m_bufferOffset = p_offset;
}

// FUNCTION: LEGO1 0x100cd090
// FUNCTION: BETA10 0x101565a0
MxBool MxDSStreamingAction::HasId(MxU32 p_objectId)
{
	return m_internalAction ? m_internalAction->HasId(p_objectId) : FALSE;
}

// FUNCTION: LEGO1 0x100cd0d0
// FUNCTION: BETA10 0x101564a0
MxDSStreamingAction::MxDSStreamingAction(MxDSStreamingAction& p_dsStreamingAction)
{
	Init();
	CopyFrom(p_dsStreamingAction);
}

// FUNCTION: LEGO1 0x100cd150
// FUNCTION: BETA10 0x1015f41d
MxDSStreamingAction::~MxDSStreamingAction()
{
	if (m_unk0xa0) {
		delete m_unk0xa0;
	}
	if (m_unk0xa4) {
		delete m_unk0xa4;
	}
	if (m_internalAction) {
		delete m_internalAction;
	}
}

// FUNCTION: LEGO1 0x100cd1e0
// FUNCTION: BETA10 0x1015f53c
void MxDSStreamingAction::Init()
{
	m_unk0x94 = 0;
	m_bufferOffset = 0;
	m_unk0x9c = 0;
	m_unk0xa0 = NULL;
	m_unk0xa4 = NULL;
	m_unk0xa8 = 0;
	m_unk0xac = 2;
	m_internalAction = NULL;
}

// FUNCTION: LEGO1 0x100cd220
// FUNCTION: BETA10 0x1015f5b9
MxDSStreamingAction* MxDSStreamingAction::CopyFrom(MxDSStreamingAction& p_dsStreamingAction)
{
	MxDSAction::operator=(p_dsStreamingAction);
	m_unk0x94 = p_dsStreamingAction.m_unk0x94;
	m_bufferOffset = p_dsStreamingAction.m_bufferOffset;
	m_unk0x9c = p_dsStreamingAction.m_unk0x9c;
	m_unk0xa0 = NULL;
	m_unk0xa4 = NULL;
	m_unk0xac = p_dsStreamingAction.m_unk0xac;
	m_unk0xa8 = p_dsStreamingAction.m_unk0xa8;
	SetInternalAction(p_dsStreamingAction.m_internalAction ? p_dsStreamingAction.m_internalAction->Clone() : NULL);

	return this;
}

// FUNCTION: LEGO1 0x100cd2a0
// FUNCTION: BETA10 0x1015f698
void MxDSStreamingAction::SetInternalAction(MxDSAction* p_dsAction)
{
	if (m_internalAction) {
		delete m_internalAction;
	}
	m_internalAction = p_dsAction;
}

// FUNCTION: LEGO1 0x100cd2d0
void MxDSStreamingAction::FUN_100cd2d0()
{
	if (m_duration == -1) {
		return;
	}

	MxLong duration = m_duration / m_loopCount;
	m_loopCount--;

	m_duration -= duration;
	m_unk0xa8 += duration;
}
