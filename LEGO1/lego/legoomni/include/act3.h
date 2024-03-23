#ifndef ACT3_H
#define ACT3_H

#include "legoworld.h"

// VTABLE: LEGO1 0x100d9628
// SIZE 0x4274
class Act3 : public LegoWorld {
public:
	Act3();

	~Act3() override; // vtable+00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x10072510
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f013c
		return "Act3";
	}

	// FUNCTION: LEGO1 0x10072520
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Act3::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void Destroy(MxBool p_fromDestructor) override;   // vtable+0x1c
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x5c() override;                     // vtable+0x5c
	void VTable0x60() override;                       // vtable+0x60
	MxBool VTable0x64() override;                     // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	inline void SetUnkown420c(MxEntity* p_entity) { m_unk0x420c = p_entity; }
	inline void SetUnkown4270(MxU32 p_unk0x4270) { m_unk0x4270 = p_unk0x4270; }

	// SYNTHETIC: LEGO1 0x10072630
	// Act3::`scalar deleting destructor'

	MxBool FUN_100727e0(LegoPathController*, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up);
	MxBool FUN_10072980(LegoPathController*, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up);
	void FUN_10073400();
	void FUN_10073430();

protected:
	undefined m_unk0xf8[0x4114]; // 0xf8
	MxEntity* m_unk0x420c;       // 0x420c
	undefined m_unk0x4210[0x60]; // 0x4210
	MxU32 m_unk0x4270;           // 0x4270
};

#endif // ACT3_H
