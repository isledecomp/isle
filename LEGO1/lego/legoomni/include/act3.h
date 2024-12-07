#ifndef ACT3_H
#define ACT3_H

#include "act3ammo.h"
#include "legogamestate.h"
#include "legostate.h"
#include "legoworld.h"

class Helicopter;

// SIZE 0x0c
struct Act3ListElement {
	undefined4 m_unk0x00[3]; // 0x00

	int operator==(Act3ListElement) const { return 0; }
	int operator<(Act3ListElement) const { return 0; }
};

// SIZE 0x10
class Act3List {
public:
	Act3List() { m_unk0x04 = 0; }

private:
	list<Act3ListElement> m_unk0x00; // 0x00
	undefined4 m_unk0x04;            // 0x0c
};

// VTABLE: LEGO1 0x100d4fc8
// SIZE 0x0c
class Act3State : public LegoState {
public:
	Act3State() { m_unk0x08 = 0; }

	// FUNCTION: LEGO1 0x1000e300
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03f0
		return "Act3State";
	}

	// FUNCTION: LEGO1 0x1000e310
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Act3State::ClassName()) || LegoState::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x1000e2f0
	MxBool IsSerializable() override { return FALSE; }

	// SYNTHETIC: LEGO1 0x1000e3c0
	// Act3State::`scalar deleting destructor'

	undefined4 GetUnknown0x08() { return m_unk0x08; }

	// TODO: Most likely getters/setters are not used according to BETA.

	undefined4 m_unk0x08; // 0x08
};

// VTABLE: LEGO1 0x100d9628
// SIZE 0x4274
class Act3 : public LegoWorld {
public:
	Act3();
	~Act3() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x10072510
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f013c
		return "Act3";
	}

	// FUNCTION: LEGO1 0x10072520
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Act3::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void Destroy(MxBool p_fromDestructor) override;   // vtable+0x1c
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x5c() override;                     // vtable+0x5c
	void VTable0x60() override;                       // vtable+0x60
	MxBool Escape() override;                         // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	void SetHelicopter(Helicopter* p_helicopter) { m_helicopter = p_helicopter; }
	void SetDestLocation(LegoGameState::Area p_destLocation) { m_destLocation = p_destLocation; }

	// SYNTHETIC: LEGO1 0x10072630
	// Act3::`scalar deleting destructor'

	MxBool FUN_100727e0(LegoPathController*, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up);
	MxBool FUN_10072980(LegoPathController*, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up);
	void FUN_10073400();
	void FUN_10073430();

protected:
	undefined4 m_unk0xf8;               // 0xf8
	Act3Ammo m_unk0xfc[20];             // 0xfc
	Act3Ammo m_unk0x217c[20];           // 0x217c
	undefined m_unk0x41fc;              // 0x41fc
	undefined4 m_unk0x4200;             // 0x4200
	undefined4 m_unk0x4204;             // 0x4204
	undefined4 m_unk0x4208;             // 0x4208
	Helicopter* m_helicopter;           // 0x420c
	undefined4 m_unk0x4210;             // 0x4210
	MxFloat m_unk0x4214;                // 0x4214
	undefined4 m_unk0x4218;             // 0x4218
	undefined m_unk0x421c;              // 0x421c
	undefined m_unk0x421d;              // 0x421d
	undefined m_unk0x421e;              // 0x421e
	Act3List m_unk0x4220;               // 0x4220
	undefined4 m_unk0x4230[15];         // 0x4230
	undefined4 m_unk0x426c;             // 0x426c
	LegoGameState::Area m_destLocation; // 0x4270
};

// TEMPLATE: LEGO1 0x10072440
// list<Act3ListElement,allocator<Act3ListElement> >::~list<Act3ListElement,allocator<Act3ListElement> >

// TEMPLATE: LEGO1 0x100724b0
// List<Act3ListElement>::~List<Act3ListElement>

// FUNCTION: LEGO1 0x10072650
// Act3List::~Act3List

#endif // ACT3_H
