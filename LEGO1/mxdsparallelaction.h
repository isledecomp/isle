#ifndef MXDSPARALLELACTION_H
#define MXDSPARALLELACTION_H

#include "mxdsmultiaction.h"

// VTABLE: LEGO1 0x100dcf80
// SIZE 0x9c
class MxDSParallelAction : public MxDSMultiAction {
public:
	MxDSParallelAction();
	virtual ~MxDSParallelAction() override;

	void CopyFrom(MxDSParallelAction& p_dsParallelAction);
	MxDSParallelAction& operator=(MxDSParallelAction& p_dsParallelAction);

	// FUNCTION: LEGO1 0x100caf00
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10102608
		return "MxDSParallelAction";
	}

	// FUNCTION: LEGO1 0x100caf10
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSParallelAction::ClassName()) || MxDSMultiAction::IsA(p_name);
	}

	virtual MxLong GetDuration() override; // vtable+24;
	virtual MxDSAction* Clone() override;  // vtable+2c;
};

#endif // MXDSPARALLELACTION_H
