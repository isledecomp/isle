#ifndef INFOCENTER_H
#define INFOCENTER_H

#include "actionsfwd.h"
#include "legogamestate.h"
#include "legostate.h"
#include "legoworld.h"
#include "mxrect32.h"
#include "radio.h"

class MxNotificationParam;
class MxStillPresenter;
class LegoControlManagerNotificationParam;

// VTABLE: LEGO1 0x100d93a8
// VTABLE: BETA10 0x101b9b88
// SIZE 0x94
class InfocenterState : public LegoState {
public:
	InfocenterState();
	~InfocenterState() override;

	// FUNCTION: LEGO1 0x10071840
	// FUNCTION: BETA10 0x10031ee0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04dc
		return "InfocenterState";
	}

	// FUNCTION: LEGO1 0x10071850
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, InfocenterState::ClassName()) || LegoState::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x10071830
	MxBool IsSerializable() override { return FALSE; } // vtable+0x14

	MxS16 GetMaxNameLength() { return sizeOfArray(m_letters); }
	MxStillPresenter* GetNameLetter(MxS32 p_index) { return m_letters[p_index]; }
	void SetNameLetter(MxS32 p_index, MxStillPresenter* p_letter) { m_letters[p_index] = p_letter; }
	MxBool HasRegistered() { return m_letters[0] != NULL; }
	Playlist& GetExitDialogueAct1() { return m_exitDialogueAct1; }
	Playlist& GetExitDialogueAct23() { return m_exitDialogueAct23; }
	Playlist& GetReturnDialogue(LegoGameState::Act p_act) { return m_returnDialogue[p_act]; }
	Playlist& GetLeaveDialogue(LegoGameState::Act p_act) { return m_leaveDialogue[p_act]; }
	Playlist& GetBricksterDialogue() { return m_bricksterDialogue; }
	MxU32 GetUnknown0x74() { return m_unk0x74; }

	void SetUnknown0x74(MxU32 p_unk0x74) { m_unk0x74 = p_unk0x74; }

	// SYNTHETIC: LEGO1 0x10071900
	// InfocenterState::`scalar deleting destructor'

	// TODO: Most likely getters/setters are not used according to BETA.

	Playlist m_exitDialogueAct1;    // 0x08
	Playlist m_exitDialogueAct23;   // 0x14
	Playlist m_returnDialogue[3];   // 0x20
	Playlist m_leaveDialogue[3];    // 0x44
	Playlist m_bricksterDialogue;   // 0x68
	MxU32 m_unk0x74;                // 0x74
	MxStillPresenter* m_letters[7]; // 0x78
};

// SIZE 0x18
struct InfocenterMapEntry {
	// FUNCTION: LEGO1 0x1006ec80
	InfocenterMapEntry() {}

	MxStillPresenter* m_presenter; // 0x00
	undefined4 m_unk0x04;          // 0x04
	MxRect32 m_area;               // 0x08
};

// VTABLE: LEGO1 0x100d9338
// VTABLE: BETA10 0x101b9b10
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
	// FUNCTION: BETA10 0x100316e0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04ec
		return "Infocenter";
	}

	// FUNCTION: LEGO1 0x1006eb50
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Infocenter::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x5c() override;                     // vtable+0x5c
	MxBool Escape() override;                         // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	// SYNTHETIC: LEGO1 0x1006ec60
	// Infocenter::`scalar deleting destructor'

private:
	void InitializeBitmaps();

	MxLong HandleKeyPress(MxS8 p_key);
	MxU8 HandleMouseMove(MxS32 p_x, MxS32 p_y);
	MxU8 HandleButtonUp(MxS32 p_x, MxS32 p_y);
	MxU8 HandleControl(LegoControlManagerNotificationParam& p_param);
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
