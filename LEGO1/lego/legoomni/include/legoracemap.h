#ifndef LEGORACEMAP_H
#define LEGORACEMAP_H

#include "legoraceactor.h"

class MxControlPresenter;
class MxStillPresenter;

// VTABLE: LEGO1 0x100d8858 LegoRaceActor
// VTABLE: LEGO1 0x100d8860 LegoAnimActor
// VTABLE: LEGO1 0x100d8870 LegoPathActor
// VTABLE: LEGO1 0x100d893c LegoRaceMap
// VTABLE: BETA10 0x101be4dc LegoRaceActor
// VTABLE: BETA10 0x101be4e0 LegoAnimActor
// VTABLE: BETA10 0x101be4f8 LegoPathActor
// VTABLE: BETA10 0x101be5e8 LegoRaceMap
// SIZE 0x1b4
class LegoRaceMap : public virtual LegoRaceActor {
public:
	LegoRaceMap();
	~LegoRaceMap() override;

	// LegoPathActor vtable
	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	void ParseAction(char* p_extra) override; // vtable+0x20
	void Animate(float p_time) override = 0;  // vtable+0x70

	// LegoRaceMap vtable
	virtual void FUN_1005d4b0(); // vtable+0x00

	// SYNTHETIC: LEGO1 0x10012c50
	// LegoRaceMap::`vbase destructor'

	// SYNTHETIC: LEGO1 0x1005d5d0
	// LegoRaceMap::`scalar deleting destructor'

private:
	MxBool m_unk0x08;                   // 0x08
	MxStillPresenter* m_stillPresenter; // 0x0c

	// variable name verified by BETA10 0x100ca82b
	MxControlPresenter* m_Map_Ctl; // 0x10

	// likely an x-offset of the race map in world space
	float m_unk0x14; // 0x14
	// inversely scales the map in x direction (either convert world->screen space or to control the size)
	float m_unk0x18; // 0x18
	// likely a y-offset of the race map in world space
	float m_unk0x1c; // 0x1c
	// inversely scales the map in y direction (either convert world->screen space or to control the size)
	float m_unk0x20; // 0x20
	// scales the map in x direction (either convert world->screen space or to change the size)
	float m_unk0x24; // 0x24
	// scales the map in y direction (either convert world->screen space or to change the size)
	float m_unk0x28; // 0x28
	// likely an x-offset of the race map in screen space
	float m_unk0x2c; // 0x2c
	// likely a y-offset of the race map in screen space
	float m_unk0x30; // 0x30
};

// GLOBAL: LEGO1 0x100d8848
// LegoRaceMap::`vbtable'

// GLOBAL: LEGO1 0x100d8840
// LegoRaceMap::`vbtable'{for `LegoAnimActor'}

// GLOBAL: LEGO1 0x100d8830
// LegoRaceMap::`vbtable'{for `LegoRaceActor'}

#endif // LEGORACEMAP_H
