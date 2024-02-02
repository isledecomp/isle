#ifndef MXCONTROLPRESENTER_H
#define MXCONTROLPRESENTER_H

#include "decomp.h"
#include "mxcompositepresenter.h"

class LegoControlManagerEvent;
class MxVideoPresenter;

// VTABLE: LEGO1 0x100d7b88
// SIZE 0x5c
class MxControlPresenter : public MxCompositePresenter {
public:
	MxControlPresenter();
	~MxControlPresenter() override;

	// FUNCTION: LEGO1 0x10044000
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0514
		return "MxControlPresenter";
	}

	// FUNCTION: LEGO1 0x10044010
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxControlPresenter::ClassName()) || MxCompositePresenter::IsA(p_name);
	}

	void ReadyTickle() override;                                     // vtable+0x18
	void RepeatingTickle() override;                                 // vtable+0x24
	void ParseExtra() override;                                      // vtable+0x30
	MxResult AddToManager() override;                                // vtable+0x34
	MxResult StartAction(MxStreamController*, MxDSAction*) override; // vtable+0x3c
	void EndAction() override;                                       // vtable+0x40
	MxBool HasTickleStatePassed(TickleState p_tickleState) override; // vtable+0x48
	void Enable(MxBool p_enable) override;                           // vtable+0x54
	MxBool VTable0x64(undefined4 p_undefined) override;              // vtable+0x64
	virtual void VTable0x68(MxBool p_unk0x50);                       // vtable+0x68
	virtual void VTable0x6c(MxS16);                                  // vtable+0x6c

	MxBool FUN_10044480(LegoControlManagerEvent* p_event, MxPresenter* p_presenter);
	MxBool FUN_10044270(MxS32 p_x, MxS32 p_y, MxVideoPresenter* p_presenter);

private:
	undefined2 m_unk0x4c; // 0x4c
	MxS16 m_unk0x4e;      // 0x4e
	MxBool m_unk0x50;     // 0x50
	undefined2 m_unk0x52; // 0x52
	undefined2 m_unk0x54; // 0x54
	undefined2 m_unk0x56; // 0x56
	MxS16* m_unk0x58;     // 0x58
};

// SYNTHETIC: LEGO1 0x100440f0
// MxControlPresenter::`scalar deleting destructor'

#endif // MXCONTROLPRESENTER_H
