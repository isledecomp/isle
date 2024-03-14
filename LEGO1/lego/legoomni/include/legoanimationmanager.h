#ifndef LEGOANIMATIONMANAGER_H
#define LEGOANIMATIONMANAGER_H

#include "animstate.h"
#include "decomp.h"
#include "mxcore.h"

struct Character {
	char* m_name;
	undefined m_unk0x4[0x10]; // 0x04
	MxBool m_active;          // 0x14
	undefined m_unk0x15;      // 0x15
	undefined m_unk0x16;      // 0x16
	undefined m_unk0x17;      // 0x17
};

struct Vehicle {
	char* m_name;        // 0x00
	undefined4 m_unk0x4; // 0x04
};

void LegoUnknown100d8ca8Handler();
void LegoUnknown100d8cd8Handler();

// VTABLE: LEGO1 0x100d8ca8
// SIZE 0x10
class LegoUnknown100d8ca8 : public MxCore {
public:
	inline LegoUnknown100d8ca8()
	{
		m_unk0x8 = 0;
		SetHandler(LegoUnknown100d8ca8Handler);
	}
	inline void SetHandler(void (*p_handler)()) { m_unk0xc = p_handler; }

private:
	MxU32 m_unk0x8;     // 0x08
	void (*m_unk0xc)(); // 0x0c
};

// VTABLE: LEGO1 0x100d8cc0
// SIZE 0x18
class LegoUnknown100d8cc0 : public LegoUnknown100d8ca8 {
public:
	inline LegoUnknown100d8cc0() { m_unk0x10 = m_unk0x14 = 0; }

private:
	MxU32 m_unk0x10; // 0x10
	MxU32 m_unk0x14; // 0x14
};

// VTABLE: LEGO1 0x100d8cd8
// SIZE 0x18
class LegoUnknown100d8cd8 : public LegoUnknown100d8cc0 {
public:
	inline LegoUnknown100d8cd8(MxBool p_mode) { SetHandler(p_mode); }
	inline void SetHandler(MxBool p_mode)
	{
		LegoUnknown100d8ca8::SetHandler(p_mode ? LegoUnknown100d8cd8Handler : LegoUnknown100d8ca8Handler);
	}
};

// VTABLE: LEGO1 0x100d8c90
// SIZE 0x18
class LegoUnknown100d8c90 : public LegoUnknown100d8cd8 {
public:
	inline LegoUnknown100d8c90() : LegoUnknown100d8cd8(FALSE) {}
};

// VTABLE: LEGO1 0x100d8c18
// SIZE 0x500
class LegoAnimationManager : public MxCore {
public:
	LegoAnimationManager();
	~LegoAnimationManager() override; // vtable+0x00

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

	void FUN_1005ee80(MxBool);
	void FUN_1005ef10();
	void FUN_1005f0b0();
	void FUN_1005f6d0(MxBool);
	MxResult LoadScriptInfo(MxS32 p_scriptIndex);
	MxBool FUN_10060140(char* p_name, MxU32& p_index);
	MxResult ReadAnimInfo(LegoFile* p_file, AnimInfo* p_info);
	MxResult ReadModelInfo(LegoFile* p_file, ModelInfo* p_info);
	void FUN_100603c0();
	void FUN_10061010(undefined4);
	void FUN_100617c0(MxS32, MxU16&, MxU32&);
	MxS8 FUN_10062360(char*);
	void FUN_10064670(MxBool);

	static void configureLegoAnimationManager(MxS32 p_legoAnimationManagerConfig);

	// SYNTHETIC: LEGO1 0x1005ed10
	// LegoAnimationManager::`scalar deleting destructor'

private:
	void Init();

	undefined4 m_unk0x08;                 // 0x08
	MxU16 m_animCount;                    // 0x0c
	MxU16 m_unk0x0e;                      // 0x0e
	MxU32 m_unk0x10;                      // 0x10
	AnimInfo* m_anims;                    // 0x14
	undefined m_unk0x018[8];              // 0x18
	LegoUnknown100d8c90* m_tranInfoList;  // 0x20
	LegoUnknown100d8c90* m_tranInfoList2; // 0x24
	undefined4 m_unk0x28[2];              // 0x28
	undefined4 m_unk0x30[2];              // 0x30
	undefined m_unk0x38;                  // 0x38
	undefined m_unk0x39;                  // 0x39
	undefined m_unk0x3a;                  // 0x3a
	undefined m_unk0x3b[0x3c1];           // 0x3b
	undefined4 m_unk0x3fc;                // 0x3fc
	MxU8 m_unk0x400;                      // 0x400
	undefined m_unk0x401;                 // 0x401
	MxU8 m_unk0x402;                      // 0x402
	undefined m_unk0x403[0x1d];           // 0x403
	AnimState* m_animState;               // 0x420
	undefined4 m_unk0x424;                // 0x424
	undefined m_unk0x428;                 // 0x428
	undefined m_unk0x429;                 // 0x429
	undefined m_unk0x42a;                 // 0x42a
	undefined m_unk0x42b;                 // 0x42b
	undefined4 m_unk0x42c;                // 0x42c
	undefined m_unk0x430;                 // 0x430
	undefined m_unk0x431[0xcf];           // 0x431
};

#endif // LEGOANIMATIONMANAGER_H
