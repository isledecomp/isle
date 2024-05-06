#ifndef LEGOBUILDINGMANAGER_H
#define LEGOBUILDINGMANAGER_H

#include "decomp.h"
#include "mxcore.h"

class LegoEntity;
class LegoROI;
class LegoStorage;
class LegoWorld;

// SIZE 0x2c
struct LegoBuildingInfo {
	enum {
		c_bit1 = 0x01,
		c_bit2 = 0x02,
		c_bit3 = 0x04,
		c_bit4 = 0x08
	};

	LegoEntity* m_entity;   // 0x00
	const char* m_hausName; // 0x04
	MxU32 m_cycle1;         // 0x08
	MxU32 m_cycle2;         // 0x0c
	MxU8 m_cycle3;          // 0x10
	MxS8 m_unk0x11;         // 0x11
	MxS8 m_initialUnk0x11;  // 0x12 = initial value loaded to m_unk0x11
	MxU8 m_flags;           // 0x13
	float m_unk0x014;       // 0x14
	const char* m_unk0x18;  // 0x18
	float m_x;              // 0x1c
	float m_y;              // 0x20
	float m_z;              // 0x24
	undefined* m_unk0x28;   // 0x28
};

// VTABLE: LEGO1 0x100d6f50
// SIZE 0x30
class LegoBuildingManager : public MxCore {
public:
	LegoBuildingManager();
	~LegoBuildingManager() override;

	MxResult Tickle() override; // vtable+0x08

	// FUNCTION: LEGO1 0x1002f930
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f37d0
		return "LegoBuildingManager";
	}

	static void configureLegoBuildingManager(MxS32);
	static void SetCustomizeAnimFile(const char* p_value);

	void Init();
	void FUN_1002fa00();
	void UpdatePosition(MxS32 p_index, LegoWorld* p_world);
	void FUN_1002fb30();
	MxResult Write(LegoStorage* p_storage);
	MxResult Read(LegoStorage* p_storage);
	LegoBuildingInfo* GetInfo(LegoEntity* p_entity);
	MxBool IncrementVariant(LegoEntity* p_entity);
	MxBool FUN_1002fe40(LegoEntity* p_entity);
	MxBool FUN_1002fe80(LegoEntity* p_entity);
	MxBool FUN_1002fed0(LegoEntity* p_entity);
	MxU32 FUN_1002ff40(LegoEntity*, MxBool);
	MxBool FUN_10030000(LegoEntity* p_entity);
	MxBool FUN_10030030(MxS32 p_index);
	MxBool FUN_10030110(LegoBuildingInfo* p_data);
	void FUN_10030590();
	void AdjustHeight(MxS32 p_index);

	// SYNTHETIC: LEGO1 0x1002f940
	// LegoBuildingManager::`scalar deleting destructor'

private:
	static char* g_customizeAnimFile;

	MxU8 m_nextVariant;   // 0x08
	MxU8 m_unk0x09;       // 0x09
	undefined4 m_unk0x0c; // 0x0c
	undefined4 m_unk0x10; // 0x10
	undefined4 m_unk0x14; // 0x14
	undefined4 m_unk0x18; // 0x18
	undefined4 m_unk0x1c; // 0x1c
	MxU8 m_unk0x20;       // 0x20
	undefined4 m_unk0x24; // 0x24
	MxU8 m_unk0x28;       // 0x28
	undefined4 m_unk0x2c; // 0x2c
};

#endif // LEGOBUILDINGMANAGER_H
