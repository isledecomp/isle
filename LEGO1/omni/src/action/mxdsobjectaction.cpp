#include "mxdsobjectaction.h"

DECOMP_SIZE_ASSERT(MxDSObjectAction, 0xb8)

// FUNCTION: LEGO1 0x100c8870
MxDSObjectAction::MxDSObjectAction()
{
	this->SetType(e_objectAction);
}

// FUNCTION: LEGO1 0x100c8a20
MxDSObjectAction::~MxDSObjectAction()
{
}

// FUNCTION: LEGO1 0x100c8a70
void MxDSObjectAction::CopyFrom(MxDSObjectAction& p_dsObjectAction)
{
}

// FUNCTION: LEGO1 0x100c8a80
MxDSObjectAction& MxDSObjectAction::operator=(MxDSObjectAction& p_dsObjectAction)
{
	if (this == &p_dsObjectAction) {
		return *this;
	}

	MxDSMediaAction::operator=(p_dsObjectAction);
	this->CopyFrom(p_dsObjectAction);
	return *this;
}

// FUNCTION: LEGO1 0x100c8ab0
MxDSAction* MxDSObjectAction::Clone()
{
	MxDSObjectAction* clone = new MxDSObjectAction();

	if (clone) {
		*clone = *this;
	}

	return clone;
}
