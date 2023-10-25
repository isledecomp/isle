#include "mxdsobjectaction.h"

DECOMP_SIZE_ASSERT(MxDSObjectAction, 0xb8)

// OFFSET: LEGO1 0x100c8870
MxDSObjectAction::MxDSObjectAction()
{
	this->SetType(MxDSType_ObjectAction);
}

// OFFSET: LEGO1 0x100c8a20
MxDSObjectAction::~MxDSObjectAction()
{
}

// OFFSET: LEGO1 0x100c8a70
void MxDSObjectAction::CopyFrom(MxDSObjectAction& p_dsObjectAction)
{
}

// OFFSET: LEGO1 0x100c8a80
MxDSObjectAction& MxDSObjectAction::operator=(MxDSObjectAction& p_dsObjectAction)
{
	if (this == &p_dsObjectAction)
		return *this;

	MxDSMediaAction::operator=(p_dsObjectAction);
	this->CopyFrom(p_dsObjectAction);
	return *this;
}

// OFFSET: LEGO1 0x100c8ab0
MxDSAction* MxDSObjectAction::Clone()
{
	MxDSObjectAction* clone = new MxDSObjectAction();

	if (clone)
		*clone = *this;

	return clone;
}
