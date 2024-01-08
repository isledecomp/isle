#ifndef ACT3_H
#define ACT3_H

#include "legoworld.h"

// VTABLE: LEGO1 0x100d9628
// SIZE 0x4274
class Act3 : public LegoWorld {
public:
	Act3();

	virtual ~Act3() override; // vtable+00

	// FUNCTION: LEGO1 0x10072510
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f013c
		return "Act3";
	}

	// FUNCTION: LEGO1 0x10072520
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Act3::ClassName()) || LegoWorld::IsA(p_name);
	}

	inline void SetUnkown420c(MxEntity* p_entity) { m_unk0x420c = p_entity; }
	inline void SetUnkown4270(MxU32 p_unk0x4270) { m_unk0x4270 = p_unk0x4270; }

protected:
	undefined m_unk0xf8[0x4114]; // 0xf8
	MxEntity* m_unk0x420c;       // 0x420c
	undefined m_unk0x4210[0x60]; // 0x4210
	MxU32 m_unk0x4270;           // 0x4270
};

#endif // ACT3_H
