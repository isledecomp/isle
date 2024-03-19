#ifndef INFOCENTER_H
#define INFOCENTER_H

#include "actionsfwd.h"
#include "legogamestate.h"
#include "legoworld.h"
#include "mxrect32.h"
#include "radio.h"

class InfocenterState;
class MxStillPresenter;
class LegoControlManagerEvent;

// SIZE 0x18
struct InfocenterMapEntry {
	// FUNCTION: LEGO1 0x1006ec80
	InfocenterMapEntry() {}

	MxStillPresenter* m_presenter; // 0x00
	undefined4 m_unk0x04;          // 0x04
	MxRect32 m_area;               // 0x08
};

// VTABLE: LEGO1 0x100d9338
// SIZE 0x1d8
class Infocenter : public LegoWorld {
public:
	enum Cutscene {
		e_noIntro = -1,
		e_legoMovie,
		e_mindscapeMovie,
		e_introMovie,
		e_outroMovie,
		e_badEndMovie,
		e_goodEndMovie
	};

	enum Character {
		e_noCharacter = 0,
		e_pepper,
		e_mama,
		e_papa,
		e_nick,
		e_laura
	};

	Infocenter();
	~Infocenter() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x1006eb40
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04ec
		return "Infocenter";
	}

	// FUNCTION: LEGO1 0x1006eb50
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Infocenter::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x5c() override;                     // vtable+0x5c
	MxBool VTable0x64() override;                     // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	// SYNTHETIC: LEGO1 0x1006ec60
	// Infocenter::`scalar deleting destructor'

private:
	void InitializeBitmaps();

	MxLong HandleKeyPress(MxS8 p_key);
	MxU8 HandleMouseMove(MxS32 p_x, MxS32 p_y);
	MxU8 HandleButtonUp(MxS32 p_x, MxS32 p_y);
	MxU8 HandleClick(LegoControlManagerEvent& p_param);
	MxLong HandleEndAction(MxEndActionNotificationParam& p_param);
	MxLong HandleNotification0(MxNotificationParam& p_param);

	void UpdateFrameHot(MxBool p_display);
	void Reset();

	void PlayCutscene(Cutscene p_entityId, MxBool p_scale);
	void StopCutscene();

	void FUN_10070d10(MxS32 p_x, MxS32 p_y);

	void StartCredits();
	void StopCredits();

	void PlayAction(InfomainScript::Script p_script);
	void StopCurrentAction();

	void PlayBookAnimation();
	void StopBookAnimation();

	InfomainScript::Script m_currentInfomainScript; // 0xf8
	MxS16 m_selectedCharacter;                      // 0xfc
	InfocenterState* m_infocenterState;             // 0x100
	LegoGameState::Area m_destLocation;             // 0x104
	Cutscene m_currentCutscene;                     // 0x108
	Radio m_radio;                                  // 0x10c
	MxStillPresenter* m_unk0x11c;                   // 0x11c
	InfocenterMapEntry m_mapAreas[7];               // 0x120
	MxS16 m_unk0x1c8;                               // 0x1c8
	MxStillPresenter* m_frameHotBitmap;             // 0x1cc
	MxS16 m_infoManDialogueTimer;                   // 0x1d0
	MxS16 m_bookAnimationTimer;                     // 0x1d2
	MxU16 m_unk0x1d4;                               // 0x1d4
	MxS16 m_unk0x1d6;                               // 0x1d6
};

#endif // INFOCENTER_H
