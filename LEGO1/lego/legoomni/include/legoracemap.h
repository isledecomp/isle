#ifndef LEGORACEMAP_H
#define LEGORACEMAP_H

#include "legoraceactor.h"

/*
	XVTABLE: LEGO1 0x100d5510 LegoRaceActor
	XVTABLE: LEGO1 0x100d5510 LegoAnimActor
	XVTABLE: LEGO1 0x100d5440 LegoPathActor
	XVTABLE: LEGO1 0x100d5510 LegoRaceMap
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
