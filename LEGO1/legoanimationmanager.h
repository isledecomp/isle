#ifndef LEGOANIMATIONMANAGER_H
#define LEGOANIMATIONMANAGER_H

#include "mxcore.h"

// VTABLE: LEGO1 0x100d8c18
// SIZE 0x500
class LegoAnimationManager : public MxCore {
public:
	LegoAnimationManager();
	virtual ~LegoAnimationManager() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p) override; // vtable+0x4
	virtual MxResult Tickle() override;         // vtable+0x8

	// FUNCTION: LEGO1 0x1005ec80
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f7508
		return "LegoAnimationManager";
	}

	// FUNCTION: LEGO1 0x1005ec90
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, ClassName()) || MxCore::IsA(name);
	}

	void FUN_1005f6d0(MxBool p);

	__declspec(dllexport) static void configureLegoAnimationManager(int param_1);

private:
	void Init();
};

#endif // LEGOANIMATIONMANAGER_H
