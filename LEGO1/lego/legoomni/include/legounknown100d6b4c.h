#ifndef LEGOUNKNOWN100D6B4C_H
#define LEGOUNKNOWN100D6B4C_H

#include "decomp.h"
#include "mxtypes.h"

class LegoCacheSound;

// VTABLE: LEGO1 0x100d6b4c
// SIZE 0x20
class LegoUnknown100d6b4c {
public:
	LegoUnknown100d6b4c();
	~LegoUnknown100d6b4c();

	virtual MxResult Tickle(); // vtable+0x00

	void FUN_1003dc40(LegoCacheSound** p_und);

private:
	undefined m_pad[0x1c];
};

#endif // LEGOUNKNOWN100D6B4C_H
