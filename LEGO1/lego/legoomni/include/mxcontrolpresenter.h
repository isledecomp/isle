#ifndef MXCONTROLPRESENTER_H
#define MXCONTROLPRESENTER_H

#include "decomp.h"
#include "mxcompositepresenter.h"

class LegoControlManagerNotificationParam;

// VTABLE: LEGO1 0x100d7b88
// VTABLE: BETA10 0x101bf5d0
// SIZE 0x5c
class MxControlPresenter : public MxCompositePresenter {
public:
	MxControlPresenter();
	~MxControlPresenter() override;

	// FUNCTION: LEGO1 0x10043fd0
	void RepeatingTickle() override {} // vtable+0x24

	// FUNCTION: LEGO1 0x10043fe0
	MxBool VTable0x64(undefined4 p_undefined) override { return m_unk0x50; } // vtable+0x64

	// FUNCTION: LEGO1 0x10043ff0
	virtual void VTable0x68(MxBool p_unk0x50) { m_unk0x50 = p_unk0x50; } // vtable+0x68

	// FUNCTION: LEGO1 0x10044000
	// FUNCTION: BETA10 0x100ebf80
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0514
		return "MxControlPresenter";
	}

	// FUNCTION: LEGO1 0x10044010
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxControlPresenter::ClassName()) || MxCompositePresenter::IsA(p_name);
	}

	void ReadyTickle() override;                                     // vtable+0x18
	void ParseExtra() override;                                      // vtable+0x30
	MxResult AddToManager() override;                                // vtable+0x34
	MxResult StartAction(MxStreamController*, MxDSAction*) override; // vtable+0x3c
	void EndAction() override;                                       // vtable+0x40
	MxBool HasTickleStatePassed(TickleState p_tickleState) override; // vtable+0x48
	void Enable(MxBool p_enable) override;                           // vtable+0x54
	virtual void UpdateEnabledChild(MxS16 p_enabledChild);           // vtable+0x6c

	MxBool Notify(LegoControlManagerNotificationParam* p_param, MxPresenter* p_presenter);
	MxBool CheckButtonDown(MxS32 p_x, MxS32 p_y, MxPresenter* p_presenter);

	MxS16 GetEnabledChild() { return m_enabledChild; }

private:
	enum {
		e_none,
		e_toggle,
		e_grid,
		e_map,
	};

	MxS16 m_style;            // 0x4c
	MxS16 m_enabledChild;     // 0x4e
	MxBool m_unk0x50;         // 0x50
	MxS16 m_columnsOrRows;    // 0x52
	MxS16 m_rowsOrColumns;    // 0x54
	MxS16 m_stateOrCellIndex; // 0x56
	MxS16* m_states;          // 0x58
};

// SYNTHETIC: LEGO1 0x100440f0
// MxControlPresenter::`scalar deleting destructor'

#endif // MXCONTROLPRESENTER_H
