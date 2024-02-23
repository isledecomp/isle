#ifndef LEGOANIMATIONMANAGER_H
#define LEGOANIMATIONMANAGER_H

#include "decomp.h"
#include "mxcore.h"

// VTABLE: LEGO1 0x100d8c18
// SIZE 0x500
class LegoAnimationManager : public MxCore {
public:
	LegoAnimationManager();
	~LegoAnimationManager() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x1005ec80
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f7508
		return "LegoAnimationManager";
	}

	// FUNCTION: LEGO1 0x1005ec90
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ClassName()) || MxCore::IsA(p_name);
	}

	void FUN_1005ee80(MxBool);
	void FUN_1005ef10();
	void FUN_1005f0b0();
	void FUN_1005f6d0(MxBool);
	void FUN_1005f720(MxS32 p_scriptIndex);
	void FUN_10061010(undefined4);
	void FUN_10064670(MxBool);

	static void configureLegoAnimationManager(MxS32 p_legoAnimationManagerConfig);

	// SYNTHETIC: LEGO1 0x1005ed10
	// LegoAnimationManager::`scalar deleting destructor'

private:
	void Init();

	undefined m_unk0x08[0x4f8]; // 0x08
};

#endif // LEGOANIMATIONMANAGER_H
