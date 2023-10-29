#ifndef MXDSSTILL_H
#define MXDSSTILL_H

#include "mxdsmediaaction.h"

// VTABLE 0x100dce60
// SIZE 0xb8
class MxDSStill : public MxDSMediaAction {
public:
	MxDSStill();
	virtual ~MxDSStill() override;

	void CopyFrom(MxDSStill& p_dsStill);
	MxDSStill& operator=(MxDSStill& p_dsStill);

	// OFFSET: LEGO1 0x100c9930
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x101025fc
		return "MxDSStill";
	}

	// OFFSET: LEGO1 0x100c9940
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxDSStill::ClassName()) || MxDSMediaAction::IsA(name);
	}

	virtual MxDSAction* Clone() override; // vtable+2c;
};

#endif // MXDSSTILL_H
