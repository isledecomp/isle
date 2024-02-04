#ifndef JUKEBOXENTITY_H
#define JUKEBOXENTITY_H

#include "legoentity.h"

// VTABLE: LEGO1 0x100da8a0
// SIZE 0x6c
class JukeBoxEntity : public LegoEntity {
public:
	JukeBoxEntity();
	~JukeBoxEntity() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x10085cc0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f02f0
		return "JukeBoxEntity";
	}

	// FUNCTION: LEGO1 0x10085cd0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, JukeBoxEntity::ClassName()) || LegoEntity::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x10085db0
	// JukeBoxEntity::`scalar deleting destructor'
};

#endif // JUKEBOXENTITY_H
