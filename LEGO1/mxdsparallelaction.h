#ifndef MXDSPARALLELACTION_H
#define MXDSPARALLELACTION_H

#include "mxdsmultiaction.h"

// VTABLE 0x100dcf80
// SIZE 0x9c
class MxDSParallelAction : public MxDSMultiAction {
public:
	MxDSParallelAction();
	virtual ~MxDSParallelAction() override;

	void CopyFrom(MxDSParallelAction& p_dsParallelAction);
	MxDSParallelAction& operator=(MxDSParallelAction& p_dsParallelAction);

	// OFFSET: LEGO1 0x100caf00
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x10102608
		return "MxDSParallelAction";
	}

	// OFFSET: LEGO1 0x100caf10
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxDSParallelAction::ClassName()) || MxDSMultiAction::IsA(name);
	}

	virtual MxLong GetDuration() override; // vtable+24;
	virtual MxDSAction* Clone() override;  // vtable+2c;
};

#endif // MXDSPARALLELACTION_H
