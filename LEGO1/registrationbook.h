#ifndef REGISTRATIONBOOK_H
#define REGISTRATIONBOOK_H

#include "legoworld.h"

// VTABLE 0x100d9928
// SIZE 0x2d0
class RegistrationBook : public LegoWorld {
public:
	RegistrationBook();
	virtual ~RegistrationBook() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p) override; // vtable+0x4

	// OFFSET: LEGO1 0x10076e10
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f04c8
		return "RegistrationBook";
	}

	// OFFSET: LEGO1 0x10076e20
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, RegistrationBook::ClassName()) || LegoWorld::IsA(name);
	}
};

#endif // REGISTRATIONBOOK_H
