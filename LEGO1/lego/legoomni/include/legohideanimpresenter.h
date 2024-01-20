#ifndef LEGOHIDEANIMPRESENTER_H
#define LEGOHIDEANIMPRESENTER_H

#include "decomp.h"
#include "legoloopinganimpresenter.h"

// VTABLE: LEGO1 0x100d9278
// SIZE 0xc4
class LegoHideAnimPresenter : public LegoLoopingAnimPresenter {
public:
	LegoHideAnimPresenter();
	virtual ~LegoHideAnimPresenter() override;

	// FUNCTION: LEGO1 0x1006d880
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f06cc
		return "LegoHideAnimPresenter";
	}

	// FUNCTION: LEGO1 0x1006d890
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ClassName()) || LegoAnimPresenter::IsA(p_name);
	}

	virtual void ReadyTickle() override;      // vtable+0x18
	virtual void StartingTickle() override;   // vtable+0x18
	virtual MxResult AddToManager() override; // vtable+0x34
	virtual void Destroy() override;          // vtable+0x38
	virtual void EndAction() override;        // vtable+0x40
	virtual void PutFrame() override;         // vtable+0x6c

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	undefined4* m_unk0xc0; // 0xc0
};

// SYNTHETIC: LEGO1 0x1006d9d0
// LegoHideAnimPresenter::`scalar deleting destructor'

#endif // LEGOHIDEANIMPRESENTER_H
