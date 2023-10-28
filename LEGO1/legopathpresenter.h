#ifndef LEGOPATHPRESENTER_H
#define LEGOPATHPRESENTER_H

#include "mxmediapresenter.h"

// VTABLEADDR 0x100d7c10
// SIZE 0x54
class LegoPathPresenter : public MxMediaPresenter {
public:
	LegoPathPresenter();

	// OFFSET: LEGO1 0x100449a0
	inline const char* ClassName() const override // vtable+0xc
	{
		// 0x100f0690
		return "LegoPathPresenter";
	}

	// OFFSET: LEGO1 0x100449b0
	inline MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoPathPresenter::ClassName()) || MxMediaPresenter::IsA(name);
	}

	virtual void RepeatingTickle() override;  // vtable+0x24
	virtual void ParseExtra() override;       // vtable+0x30
	virtual MxResult AddToManager() override; // vtable+0x34
	virtual void Destroy() override;          // vtable+0x38

private:
	void Init();

protected:
	void Destroy(MxBool p_fromDestructor);

	MxAtomId m_atomId; // 0x50
};

#endif // LEGOPATHPRESENTER_H
