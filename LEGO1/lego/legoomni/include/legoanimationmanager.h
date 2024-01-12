#ifndef LEGOANIMATIONMANAGER_H
#define LEGOANIMATIONMANAGER_H

#include "decomp.h"
#include "mxcore.h"

// VTABLE: LEGO1 0x100d8c18
// SIZE 0x500
class LegoAnimationManager : public MxCore {
public:
	LegoAnimationManager();
	virtual ~LegoAnimationManager() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4
	virtual MxResult Tickle() override;               // vtable+0x8

	// FUNCTION: LEGO1 0x1005ec80
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f7508
		return "LegoAnimationManager";
	}

	// FUNCTION: LEGO1 0x1005ec90
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ClassName()) || MxCore::IsA(p_name);
	}

	void FUN_1005f6d0(MxBool);
	void FUN_1005f720(undefined4);
	void FUN_10064670(MxBool);

	__declspec(dllexport) static void configureLegoAnimationManager(MxS32 p_legoAnimationManagerConfig);

private:
	void Init();
};

#endif // LEGOANIMATIONMANAGER_H
