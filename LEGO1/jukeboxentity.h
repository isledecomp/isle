#ifndef JUKEBOXENTITY_H
#define JUKEBOXENTITY_H

#include "legoentity.h"

// VTABLE: LEGO1 0x100da8a0
// SIZE 0x6c
class JukeBoxEntity : public LegoEntity {
public:
	JukeBoxEntity();
	virtual ~JukeBoxEntity() override; // vtable+0x0

	// FUNCTION: LEGO1 0x10085cc0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f02f0
		return "JukeBoxEntity";
	}

	// FUNCTION: LEGO1 0x10085cd0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, JukeBoxEntity::ClassName()) || LegoEntity::IsA(name);
	}
};

#endif // JUKEBOXENTITY_H
