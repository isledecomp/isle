#ifndef LEGOBUILDINGMANAGER_H
#define LEGOBUILDINGMANAGER_H

#include "decomp.h"
#include "mxcore.h"

class LegoEntity;
class LegoROI;
class LegoWorld;
struct LegoBuildingData;
class LegoStorage;

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
	void UpdatePosition(int p_index, LegoWorld* p_world);
	void FUN_1002fb30();
	MxResult Write(LegoStorage* p_storage);
	MxResult Read(LegoStorage* p_storage);
	LegoBuildingData* GetData(LegoEntity* p_entity);
	MxBool IncrementVariant(LegoEntity* p_entity);
	MxBool FUN_1002fe40(LegoEntity* p_entity);
	MxBool FUN_1002fe80(LegoEntity* p_entity);
	MxBool FUN_1002fed0(LegoEntity* p_entity);
	MxU32 FUN_1002ff40(LegoEntity*, MxBool);
	MxBool FUN_10030000(LegoEntity* p_entity);
	MxBool FUN_10030030(int p_index);
	MxBool FUN_10030110(LegoBuildingData* p_data);
	void FUN_10030590();
	void AdjustHeight(int p_index);

	// SYNTHETIC: LEGO1 0x1002f940
	// LegoBuildingManager::`scalar deleting destructor'

private:
	static char* g_customizeAnimFile;

	MxU8 m_nextVariant; // 0x08
	MxU8 m_unk0x09;
	void* m_pSomething;
	undefined4 m_unk0x10; // 0x10
	undefined4 m_unk0x14;
	undefined4 m_unk0x18;
	undefined4 m_unk0x1c;
	MxU8 m_unk0x20; // 0x20
	undefined4 m_unk0x24;
	MxU8 m_unk0x28;       // 0x28
	undefined4 m_unk0x2c; // 0x2c
};

#endif // LEGOBUILDINGMANAGER_H
