#ifndef ACT3_H
#define ACT3_H

#include "act3ammo.h"
#include "legogamestate.h"
#include "legostate.h"
#include "legoworld.h"

class Act3Brickster;
class Act3Cop;
class Act3Shark;
class Helicopter;

// Macros confirmed by BETA10
#define MAX_PIZZAS 20
#define MAX_DONUTS 20

// SIZE 0x0c
struct Act3ListElement {
	MxU32 m_objectId;     // 0x00
	undefined4 m_unk0x04; // 0x04
	undefined m_unk0x08;  // 0x08

	Act3ListElement() {}

	Act3ListElement(MxU32 p_objectId, undefined4 p_unk0x04, undefined p_unk0x08)
		: m_objectId(p_objectId), m_unk0x04(p_unk0x04), m_unk0x08(p_unk0x08)
	{
	}

	int operator==(Act3ListElement) const { return 0; }
	int operator<(Act3ListElement) const { return 0; }
};

// SIZE 0x10
class Act3List : private list<Act3ListElement> {
public:
	Act3List() { m_unk0x0c = 0; }

	void Insert(MxS32 p_objectId, MxS32 p_option);
	void FUN_10071fa0();
	void Clear();
	void FUN_100720d0(MxU32 p_objectId);

private:
	undefined4 m_unk0x0c; // 0x0c
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

	void SetHelicopter(Helicopter* p_copter) { m_copter = p_copter; }
	void SetShark(Act3Shark* p_shark) { m_shark = p_shark; }
	void SetDestLocation(LegoGameState::Area p_destLocation) { m_destLocation = p_destLocation; }

	// SYNTHETIC: LEGO1 0x10072630
	// Act3::`scalar deleting destructor'

	void EatPizza(MxS32 p_index);
	void EatDonut(MxS32 p_index);
	void RemovePizza(Act3Ammo& p_p);
	void RemoveDonut(Act3Ammo& p_p);
	MxResult ShootPizza(LegoPathController* p_controller, Vector3& p_location, Vector3& p_direction, Vector3& p_up);
	MxResult ShootDonut(LegoPathController* p_controller, Vector3& p_location, Vector3& p_direction, Vector3& p_up);
	void FUN_10072ad0(undefined4 p_param1);
	MxResult FUN_10073360(Act3Ammo& p_ammo, const Vector3& p_param2);
	MxResult FUN_10073390(Act3Ammo& p_ammo, const Vector3& p_param2);
	void SetBrickster(Act3Brickster* p_brickster);
	void AddCop(Act3Cop* p_cop);
	void FUN_10073400();
	void FUN_10073430();
	void GoodEnding(const Matrix4& p_destination);
	void BadEnding(const Matrix4& p_destination);
	void FUN_10073a60();

	// BETA indicates that the following classes access certain members directly.
	friend class Act3Ammo;
	friend class Act3Brickster;
	friend class Act3Cop;
	friend class Act3Shark;

protected:
	MxLong HandleTransitionEnd();

	static void DebugPrintf(const char* p_format, ...);
	static void DebugCopter(
		const Matrix4& p_copter,
		const Matrix4& p_destination,
		const Matrix4& p_startPosition,
		const Matrix4& p_endPosition,
		const UnknownMx4DPointFloat& p_unk0x1f4
	);

	Act3State* m_state;                 // 0xf8
	Act3Ammo m_pizzas[MAX_PIZZAS];      // 0xfc
	Act3Ammo m_donuts[MAX_DONUTS];      // 0x217c
	undefined m_unk0x41fc;              // 0x41fc
	Act3Cop* m_cop1;                    // 0x4200
	Act3Cop* m_cop2;                    // 0x4204
	Act3Brickster* m_brickster;         // 0x4208
	Helicopter* m_copter;               // 0x420c
	Act3Shark* m_shark;                 // 0x4210
	MxFloat m_time;                     // 0x4214
	MxU8 m_unk0x4218;                   // 0x4218
	MxU8 m_unk0x4219;                   // 0x4219
	MxU8 m_unk0x421a;                   // 0x421a
	MxU8 m_unk0x421b;                   // 0x421b
	MxU8 m_unk0x421c;                   // 0x421c
	MxU8 m_unk0x421d;                   // 0x421d
	undefined m_unk0x421e;              // 0x421e
	Act3List m_unk0x4220;               // 0x4220
	MxPresenter* m_helicopterDots[15];  // 0x4230
	Act3Script::Script m_unk0x426c;     // 0x426c
	LegoGameState::Area m_destLocation; // 0x4270
};

// TEMPLATE: LEGO1 0x10071f10
// list<Act3ListElement,allocator<Act3ListElement> >::insert

// TEMPLATE: LEGO1 0x10071f70
// list<Act3ListElement,allocator<Act3ListElement> >::_Buynode

// TEMPLATE: LEGO1 0x10072220
// list<Act3ListElement,allocator<Act3ListElement> >::erase

// TEMPLATE: LEGO1 0x10072440
// list<Act3ListElement,allocator<Act3ListElement> >::~list<Act3ListElement,allocator<Act3ListElement> >

// TEMPLATE: LEGO1 0x100724b0
// List<Act3ListElement>::~List<Act3ListElement>

// FUNCTION: LEGO1 0x10072650
// Act3List::~Act3List

#endif // ACT3_H
