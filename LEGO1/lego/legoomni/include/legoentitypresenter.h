#ifndef LEGOENTITYPRESENTER_H
#define LEGOENTITYPRESENTER_H

#include "mxcompositepresenter.h"

class LegoEntity;

// VTABLE: LEGO1 0x100d8398
// SIZE 0x50
class LegoEntityPresenter : public MxCompositePresenter {
public:
	LegoEntityPresenter();
	virtual ~LegoEntityPresenter() override; // vtable+0x0

	// FUNCTION: LEGO1 0x100534b0
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f06b8
		return "LegoEntityPresenter";
	}

	// FUNCTION: LEGO1 0x100534c0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoEntityPresenter::ClassName()) || MxCompositePresenter::IsA(p_name);
	}

	virtual void ReadyTickle() override;                                                           // vtable+0x18
	virtual void RepeatingTickle() override;                                                       // vtable+0x24
	virtual void ParseExtra() override;                                                            // vtable+0x30
	virtual void Destroy() override;                                                               // vtable+0x38
	virtual MxResult StartAction(MxStreamController* p_controller, MxDSAction* p_action) override; // vtable+0x3c
	virtual void Init();                                                                           // vtable+0x68
	virtual undefined4 SetEntity(LegoEntity* p_entity);                                            // vtable+0x6c

	void SetEntityLocation(Mx3DPointFloat& p_location, Mx3DPointFloat& p_direction, Mx3DPointFloat& p_up);

	// SYNTHETIC: LEGO1 0x100535a0
	// LegoEntityPresenter::`scalar deleting destructor'

private:
	void Destroy(MxBool p_fromDestructor);

protected:
	LegoEntity* m_entity; // 0x4c
};

#endif // LEGOENTITYPRESENTER_H
