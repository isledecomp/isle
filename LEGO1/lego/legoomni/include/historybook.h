#ifndef HISTORYBOOK_H
#define HISTORYBOOK_H

#include "legoworld.h"

// VTABLE: LEGO1 0x100da328
// SIZE 0x3e4
class HistoryBook : public LegoWorld {
public:
	HistoryBook();
	virtual ~HistoryBook() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4

	// FUNCTION: LEGO1 0x10082390
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04bc
		return "HistoryBook";
	}

	// FUNCTION: LEGO1 0x100823a0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, HistoryBook::ClassName()) || LegoWorld::IsA(p_name);
	}

	virtual MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	virtual void VTable0x50() override;                       // vtable+0x50
	virtual MxBool VTable0x64() override;                     // vtable+0x64

	// SYNTHETIC: LEGO1 0x100824b0
	// HistoryBook::`scalar deleting destructor'
};

#endif // HISTORYBOOK_H
