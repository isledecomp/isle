#ifndef INFOCENTER_H
#define INFOCENTER_H

#include "legoworld.h"
#include "radio.h"

class InfocenterState;

// SIZE 0x18
struct InfocenterUnkDataEntry {
	// FUNCTION: LEGO1 0x1006ec80
	InfocenterUnkDataEntry() {}

	undefined m_pad[0x18];
};

// VTABLE: LEGO1 0x100d9338
// SIZE 0x1d8
class Infocenter : public LegoWorld {
public:
	Infocenter();
	virtual ~Infocenter() override;

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4
	virtual MxResult Tickle() override;               // vtable+0x8

	// FUNCTION: LEGO1 0x1006eb40
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04ec
		return "Infocenter";
	}

	// FUNCTION: LEGO1 0x1006eb50
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Infocenter::ClassName()) || LegoWorld::IsA(p_name);
	}

	virtual MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	virtual void VTable0x50() override;                       // vtable+0x50
	virtual MxBool VTable0x5c() override;                     // vtable+0x5c
	virtual MxBool VTable0x64() override;                     // vtable+0x64
	virtual void VTable0x68(MxBool p_add) override;           // vtable+0x68

private:
	void PlayCutScene(MxU32 p_entityId, MxBool p_scale);
	void InitializeBitmaps();

	// notifications
	MxLong HandleMouseMove(MxS32 p_x, MxS32 p_y);
	MxU8 HandleKeyPress(char p_key);
	MxU8 HandleButtonUp(MxS32 p_x, MxS32 p_y);
	MxU8 HandleNotification17(MxParam&);
	MxLong HandleEndAction(MxParam&);
	MxLong HandleNotification0(MxParam&);

	void FUN_10070e90();

	// utility functions
	void StartCredits();
	static void DeleteCredits();
	void PlayDialogue(MxS32 p_objectId);
	void StopCurrentDialogue();
	static void PlayBookAnimation();
	static void StopBookAnimation();

	MxS32 m_unk0xf8;                     // 0xf8
	MxS16 m_unk0xfc;                     // 0xfc
	InfocenterState* m_infocenterState;  // 0x100
	undefined4 m_unk0x104;               // 0x104
	MxS32 m_currentCutScene;             // 0x108
	Radio m_radio;                       // 0x10c
	undefined4 m_unk0x11c;               // 0x11c
	InfocenterUnkDataEntry m_entries[7]; // 0x120
	MxS16 m_unk0x1c8;                    // 0x1c8
	undefined4 m_unk0x1cc;               // 0x1cc
	MxU16 m_unk0x1d0;                    // 0x1d0
	MxU16 m_unk0x1d2;                    // 0x1d2
	MxU16 m_unk0x1d4;                    // 0x1d4
	MxU16 m_unk0x1d6;                    // 0x1d6
};

#endif // INFOCENTER_H
