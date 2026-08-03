// Declaration-record carrier (dial campaign, PRE): samples this translation
// unit's accumulated declaration state before the include block. [21 units]
class RkRtM0 {
	void m0() {}
};
class RkRtM1 {
	void m1() {}
};
class RkRtF0;

// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordPB {
	inline void Record0() {}
	inline void Record1() {}
};

#include "mxdsobjectaction.h"

DECOMP_SIZE_ASSERT(MxDSObjectAction, 0xb8)

// FUNCTION: LEGO1 0x100c8870
// FUNCTION: BETA10 0x1015c3b0
MxDSObjectAction::MxDSObjectAction()
{
	m_type = e_objectAction;
}

// FUNCTION: LEGO1 0x100c8a20
// FUNCTION: BETA10 0x1015c428
MxDSObjectAction::~MxDSObjectAction()
{
}

// FUNCTION: LEGO1 0x100c8a70
// FUNCTION: BETA10 0x1015c490
void MxDSObjectAction::CopyFrom(MxDSObjectAction& p_dsObjectAction)
{
}

// FUNCTION: BETA10 0x1015c4a8
MxDSObjectAction::MxDSObjectAction(MxDSObjectAction& p_dsObjectAction) : MxDSMediaAction(p_dsObjectAction)
{
	CopyFrom(p_dsObjectAction);
}

// FUNCTION: LEGO1 0x100c8a80
// FUNCTION: BETA10 0x1015c529
MxDSObjectAction& MxDSObjectAction::operator=(MxDSObjectAction& p_dsObjectAction)
{
	if (&p_dsObjectAction == this) {
		return *this;
	}

	MxDSMediaAction::operator=(p_dsObjectAction);
	CopyFrom(p_dsObjectAction);
	return *this;
}

// FUNCTION: LEGO1 0x100c8ab0
// FUNCTION: BETA10 0x1015c573
MxDSAction* MxDSObjectAction::Clone()
{
	MxDSObjectAction* clone = new MxDSObjectAction();

	if (clone) {
		*clone = *this;
	}

	return clone;
}
