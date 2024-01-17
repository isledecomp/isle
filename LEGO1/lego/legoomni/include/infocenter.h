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
	enum IntroScript {
		e_noIntro = -1,
		e_legoMovie,
		e_mindscapeMovie,
		e_introMovie,
		e_outroMovie,
		e_badEndMovie,
		e_goodEndMovie
	};

	enum InfomainScript {
		e_noInfomain = -1,
		e_welcomeDialogue = 500,
		e_randomDialogue1 = 502,
		e_letsGetStarted = 504,
		e_returnBack = 514,
		e_exitConfirmation = 522,
		e_goodEndingDialogue = 539,
		e_badEndingDialogue = 540,
		e_pepperCharacterSelect = 541,
		e_mamaCharacterSelect = 542,
		e_papaCharacterSelect = 543,
		e_officierCharacterSelect = 544,
		e_loraCharacterSelect = 545,
	};

	enum SndAmimScript {
		e_bookWig = 400
	};

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
	void InitializeBitmaps();

	MxLong HandleKeyPress(MxS8 p_key);
	MxU8 HandleMouseMove(MxS32 p_x, MxS32 p_y);
	MxU8 HandleButtonUp(MxS32 p_x, MxS32 p_y);
	MxU8 HandleNotification17(MxParam&);
	MxLong HandleEndAction(MxParam& p_param);
	MxLong HandleNotification0(MxParam&);

	void FUN_10070dc0(MxBool);
	void FUN_10070e90();

	void PlayCutscene(IntroScript p_entityId, MxBool p_scale);
	void StopCutscene();
	void StartCredits();

	void PlayDialogue(InfomainScript p_objectId);
	void StopCurrentDialogue();

	void PlayBookAnimation();
	void StopBookAnimation();

	static void StopCredits();

	InfomainScript m_currentInfomainScript; // 0xf8
	MxS16 m_unk0xfc;                        // 0xfc
	InfocenterState* m_infocenterState;     // 0x100
	undefined4 m_unk0x104;                  // 0x104
	IntroScript m_currentIntroScript;       // 0x108
	Radio m_radio;                          // 0x10c
	undefined4 m_unk0x11c;                  // 0x11c
	InfocenterUnkDataEntry m_entries[7];    // 0x120
	MxS16 m_unk0x1c8;                       // 0x1c8
	undefined4 m_unk0x1cc;                  // 0x1cc
	MxU16 m_unk0x1d0;                       // 0x1d0
	MxU16 m_unk0x1d2;                       // 0x1d2
	MxU16 m_unk0x1d4;                       // 0x1d4
	MxU16 m_unk0x1d6;                       // 0x1d6
};

#endif // INFOCENTER_H
