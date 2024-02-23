#ifndef LEGOPATHPRESENTER_H
#define LEGOPATHPRESENTER_H

#include "mxmediapresenter.h"

// VTABLE: LEGO1 0x100d7c10
// SIZE 0x54
class LegoPathPresenter : public MxMediaPresenter {
public:
	LegoPathPresenter();
	~LegoPathPresenter() override;

	// FUNCTION: LEGO1 0x100449a0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0690
		return "LegoPathPresenter";
	}

	// FUNCTION: LEGO1 0x100449b0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoPathPresenter::ClassName()) || MxMediaPresenter::IsA(p_name);
	}

	void ReadyTickle() override;      // vtable+0x18
	void StreamingTickle() override;  // vtable+0x20
	void RepeatingTickle() override;  // vtable+0x24
	void ParseExtra() override;       // vtable+0x30
	MxResult AddToManager() override; // vtable+0x34
	void Destroy() override;          // vtable+0x38

	// SYNTHETIC: LEGO1 0x10044a90
	// LegoPathPresenter::`scalar deleting destructor'

private:
	void Init();

protected:
	void Destroy(MxBool p_fromDestructor);

	MxAtomId m_atomId; // 0x50
};

#endif // LEGOPATHPRESENTER_H
