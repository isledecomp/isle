#ifndef LEGORACEMAP_H
#define LEGORACEMAP_H

#include "legoraceactor.h"

/*
	VTABLE: LEGO1 0x100d8858 LegoRaceActor
	VTABLE: LEGO1 0x100d8860 LegoAnimActor
	VTABLE: LEGO1 0x100d8870 LegoPathActor
	VTABLE: LEGO1 0x100d893c LegoRaceMap
*/
// SIZE 0x1b4
class LegoRaceMap : public virtual LegoRaceActor {
public:
	LegoRaceMap();

	virtual void FUN_1005d4b0();

	// SYNTHETIC: LEGO1 0x1005d5c0
	// LegoRaceMap::`scalar deleting destructor'

private:
	MxBool m_unk0x08;     // 0x08
	void* m_unk0x0c;      // 0x0c
	undefined4 m_unk0x10; // 0x10
	float m_unk0x14;      // 0x14
	float m_unk0x18;      // 0x18
	float m_unk0x1c;      // 0x1c
	float m_unk0x20;      // 0x20
	float m_unk0x24;      // 0x24
	float m_unk0x28;      // 0x28
	float m_unk0x2c;      // 0x2c
	undefined4 m_unk0x30; // 0x30
};

#endif // LEGORACEMAP_H
