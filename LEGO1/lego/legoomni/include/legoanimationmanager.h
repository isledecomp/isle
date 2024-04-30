#ifndef LEGOANIMATIONMANAGER_H
#define LEGOANIMATIONMANAGER_H

#include "actionsfwd.h"
#include "animstate.h"
#include "decomp.h"
#include "legoentity.h"
#include "legotraninfolist.h"
#include "mxcore.h"

class LegoAnimPresenter;
class LegoROIList;

// SIZE 0x18
struct Character {
	char* m_name;        // 0x00
	MxBool m_unk0x04;    // 0x04
	MxS8 m_vehicleId;    // 0x05
	undefined m_unk0x06; // 0x06 (unused?)
	MxBool m_unk0x07;    // 0x07
	MxBool m_unk0x08;    // 0x08
	MxBool m_unk0x09;    // 0x09
	MxU32 m_unk0x0c;     // 0x0c
	MxU32 m_unk0x10;     // 0x10
	MxBool m_active;     // 0x14
	MxU8 m_unk0x15;      // 0x15
	MxU8 m_unk0x16;      // 0x16
};

// SIZE 0x08
struct Vehicle {
	char* m_name;        // 0x00
	undefined m_unk0x04; // 0x04
	MxBool m_unk0x05;    // 0x05
};

// SIZE 0x18
struct Unknown0x3c {
	LegoROI* m_roi;            // 0x00
	MxS32 m_characterId;       // 0x04
	undefined m_unk0x08[0x08]; // 0x08
	float m_unk0x10;           // 0x10
	MxBool m_unk0x14;          // 0x14
};

// VTABLE: LEGO1 0x100d8c18
// SIZE 0x500
class LegoAnimationManager : public MxCore {
public:
	LegoAnimationManager();
	~LegoAnimationManager() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x1005ec80
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f7508
		return "LegoAnimationManager";
	}

	// FUNCTION: LEGO1 0x1005ec90
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ClassName()) || MxCore::IsA(p_name);
	}

	void Reset(MxBool p_und);
	void Suspend();
	void Resume();
	void FUN_1005f6d0(MxBool p_unk0x400);
	void FUN_1005f700(MxBool p_unk0x3a);
	MxResult LoadScriptInfo(MxS32 p_scriptIndex);
	MxBool FindVehicle(const char* p_name, MxU32& p_index);
	MxResult ReadAnimInfo(LegoFile* p_file, AnimInfo* p_info);
	MxResult ReadModelInfo(LegoFile* p_file, ModelInfo* p_info);
	void FUN_10060570(MxBool);
	MxResult StartEntityAction(MxDSAction& p_dsAction, LegoEntity* p_entity);
	MxResult FUN_10060dc0(
		IsleScript::Script p_objectId,
		MxMatrix* p_matrix,
		undefined p_param3,
		undefined p_param4,
		undefined4 p_param5,
		undefined p_param6,
		MxBool p_param7,
		MxBool p_param8,
		undefined p_param9
	);
	void FUN_10061010(undefined4);
	void FUN_100617c0(MxS32, MxU16&, MxU16&);
	LegoTranInfo* GetTranInfo(MxU32 p_index);
	void FUN_10062770();
	void FUN_100627d0(MxBool);
	void FUN_100629b0(MxU32, MxBool);
	void FUN_10063270(LegoROIList*, LegoAnimPresenter*);
	void FUN_10063780(LegoROIList* p_list);
	void FUN_10064670(MxBool);
	void FUN_10064740(MxBool);

	static void configureLegoAnimationManager(MxS32 p_legoAnimationManagerConfig);

	// SYNTHETIC: LEGO1 0x1005ed10
	// LegoAnimationManager::`scalar deleting destructor'

private:
	void Init();
	MxResult FUN_100605e0(
		MxU32 p_index,
		MxU8 p_unk0x0a,
		MxMatrix* p_matrix,
		undefined,
		undefined4,
		undefined,
		MxBool,
		MxBool,
		undefined
	);
	MxResult FUN_100609f0(MxU32 p_objectId, MxMatrix* p_matrix, MxBool p_und1, MxBool p_und2);
	void DeleteAnimations();
	MxS8 GetCharacterIndex(const char* p_name);
	void FUN_10063aa0();

	MxU32 m_scriptIndex;               // 0x08
	MxU16 m_animCount;                 // 0x0c
	MxU16 m_unk0x0e;                   // 0x0e
	MxU16 m_unk0x10;                   // 0x10
	AnimInfo* m_anims;                 // 0x14
	undefined2 m_unk0x18;              // 0x18
	undefined m_unk0x1a;               // 0x1a
	MxU32 m_unk0x1c;                   // 0x1c
	LegoTranInfoList* m_tranInfoList;  // 0x20
	LegoTranInfoList* m_tranInfoList2; // 0x24
	MxPresenter* m_unk0x28[2];         // 0x28
	MxLong m_unk0x30[2];               // 0x30
	MxBool m_unk0x38;                  // 0x38
	MxBool m_unk0x39;                  // 0x39
	MxBool m_unk0x3a;                  // 0x3a
	Unknown0x3c m_unk0x3c[40];         // 0x3c
	undefined4 m_unk0x3fc;             // 0x3fc
	MxBool m_unk0x400;                 // 0x400
	undefined m_unk0x401;              // 0x401
	MxU8 m_unk0x402;                   // 0x402
	MxLong m_unk0x404;                 // 0x404
	MxLong m_unk0x408;                 // 0x408
	MxLong m_unk0x40c;                 // 0x40c
	undefined4 m_unk0x410;             // 0x410
	undefined4 m_unk0x414;             // 0x414
	undefined4 m_unk0x418;             // 0x418
	undefined4 m_unk0x41c;             // 0x41c
	AnimState* m_animState;            // 0x420
	LegoROIList* m_unk0x424;           // 0x424
	MxBool m_unk0x428;                 // 0x428
	MxBool m_unk0x429;                 // 0x429
	undefined m_unk0x42a;              // 0x42a
	MxBool m_suspended;                // 0x42b
	undefined4 m_unk0x42c;             // 0x42c
	undefined m_unk0x430;              // 0x430
	undefined4 m_unk0x434[2];          // 0x434
	MxMatrix m_unk0x43c;               // 0x43c
	MxMatrix m_unk0x484;               // 0x484
	UnknownMx4DPointFloat m_unk0x4cc;  // 0x4cc
};

#endif // LEGOANIMATIONMANAGER_H
