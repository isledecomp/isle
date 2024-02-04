#ifndef MXDSOBJECTACTION_H
#define MXDSOBJECTACTION_H

#include "mxdsmediaaction.h"

// VTABLE: LEGO1 0x100dccf8
// SIZE 0xb8
class MxDSObjectAction : public MxDSMediaAction {
public:
	MxDSObjectAction();
	~MxDSObjectAction() override;

	MxDSObjectAction& operator=(MxDSObjectAction& p_dsObjectAction);

	// FUNCTION: LEGO1 0x100c88e0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x101025c4
		return "MxDSObjectAction";
	}

	// FUNCTION: LEGO1 0x100c88f0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSObjectAction::ClassName()) || MxDSMediaAction::IsA(p_name);
	}

	MxDSAction* Clone() override;                              // vtable+2c;
	virtual void CopyFrom(MxDSObjectAction& p_dsObjectAction); // vtable+44;

	// SYNTHETIC: LEGO1 0x100c8a00
	// MxDSObjectAction::`scalar deleting destructor'
};

#endif // MXDSOBJECTACTION_H
