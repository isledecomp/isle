#ifndef LEGOPATHSTRUCT_H
#define LEGOPATHSTRUCT_H

#include "decomp.h"
#include "mxatom.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d7d9c
// SIZE 0x0c
struct LegoPathStructBase {
public:
	LegoPathStructBase() : m_name(NULL), m_unk0x08(0) {}

	// FUNCTION: LEGO1 0x10047420
	virtual ~LegoPathStructBase()
	{
		if (m_name != NULL) {
			delete[] m_name;
		}
	}

	char* m_name;         // 0x04
	undefined4 m_unk0x08; // 0x08
};

// VTABLE: LEGO1 0x100d7da0
// SIZE 0x14
struct LegoPathStruct : public LegoPathStructBase {
public:
	// FUNCTION: LEGO1 0x100473a0
	LegoPathStruct() : m_unk0x0c(0) {}

	// FUNCTION: LEGO1 0x10047470
	~LegoPathStruct() override {}

	void VTable0x04(undefined4, undefined4, undefined4); // vtable+0x04

	undefined4 m_unk0x0c; // 0x0c
	MxAtomId m_atomId;    // 0x10
};

// SYNTHETIC: LEGO1 0x10047440
// LegoPathStructBase::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10047890
// LegoPathStruct::`vector deleting destructor'

#endif // LEGOPATHSTRUCT_H
