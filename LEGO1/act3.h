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
		// GLOBAL: LEGO1 0x100f013c
		return "Act3";
	}

	// FUNCTION: LEGO1 0x10072520
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, Act3::ClassName()) || LegoWorld::IsA(name);
	}

	inline void SetUnkown420c(MxEntity* p_entity) { m_unk420c = p_entity; }

protected:
	undefined m_unkf8[0x4114];
	MxEntity* m_unk420c;
	undefined m_unk4210[0x64];
};

#endif // ACT3_H
