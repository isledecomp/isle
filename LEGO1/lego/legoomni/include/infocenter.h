#ifndef INFOCENTER_H
#define INFOCENTER_H

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

	enum InfomainScript {
		c_noInfomain = -1,

		c_leftArrowCtl = 1,
		c_rightArrowCtl = 2,
		c_infoCtl = 3,
		c_doorCtl = 4,
		c_boatCtl = 10,
		c_raceCtl = 11,
		c_pizzaCtl = 12,
		c_gasCtl = 13,
		c_medCtl = 14,
		c_copCtl = 15,
		c_bigInfoCtl = 16,
		c_bookCtl = 17,
		c_radioCtl = 18,
		c_mamaCtl = 21,
		c_papaCtl = 22,
		c_pepperCtl = 23,
		c_nickCtl = 24,
		c_lauraCtl = 25,

		c_mamaSelected = 30,
		c_papaSelected = 31,
		c_pepperSelected = 32,
		c_nickSelected = 33,
		c_lauraSelected = 34,

		c_mamaMovie = 40,
		c_papaMovie = 41,
		c_pepperMovie = 42,
		c_nickMovie = 43,
		c_lauraMovie = 44,

		c_goToRegBook = 70,
		c_goToRegBookRed = 71,

		c_unk499 = 499,

		c_welcomeDialogue = 500,
		c_goodJobDialogue = 501,

		c_clickOnInfomanDialogue = 502,
		c_tickleInfomanDialogue = 503,

		c_letsGetStartedDialogue = 504,

		c_clickOnObjectsGuidanceDialogue = 505,
		c_arrowNavigationGuidanceDialogue = 506,
		c_elevatorGuidanceDialogue = 507,
		c_radioGuidanceDialogue = 508,
		c_exitGuidanceDialogue1 = 509,
		c_exitGuidanceDialogue2 = 510,
		c_goOutsideGuidanceDialogue = 511,
		c_experimentGuidanceDialogue = 512,
		c_returnBackGuidanceDialogue1 = 513,
		c_returnBackGuidanceDialogue2 = 514,
		c_bricksterWarningDialogue = 515,
		c_newGameGuidanceDialogue = 516,
		c_returnBackGuidanceDialogue3 = 517,

		c_reenterInfoCenterDialogue1 = 518,
		c_reenterInfoCenterDialogue2 = 519,
		c_reenterInfoCenterDialogue3 = 520,
		c_reenterInfoCenterDialogue4 = 521,

		c_exitConfirmationDialogue = 522,
		c_saveGameOptionsDialogueUnused = 523,
		c_exitGameDialogue = 524,

		c_bricksterEscapedDialogue1 = 525,
		c_bricksterEscapedDialogue2 = 526,
		c_bricksterEscapedDialogue3 = 527,
		c_bricksterEscapedDialogue4 = 528,
		c_bricksterEscapedDialogue5 = 529,
		c_bricksterEscapedDialogue6 = 530,
		c_bricksterEscapedDialogue7 = 531,

		c_infomanHiccup = 532,
		c_infomanWalkOffScreenLeftUnused = 533,
		c_infomanSneeze = 534,
		c_infomanWalkOffScreenRightUnused = 535,
		c_infomanLaughs = 536,
		c_infomanLooksBehindAtScreenUnused = 537,
		c_infomanReturnsFromScreenUnused = 538,

		c_goodEndingDialogue = 539,
		c_badEndingDialogue = 540,

		c_pepperCharacterSelect = 541,
		c_mamaCharacterSelect = 542,
		c_papaCharacterSelect = 543,
		c_nickCharacterSelect = 544,
		c_lauraCharacterSelect = 545,

		c_creditsDialogue = 551,

		c_noCDDialogueUnused1 = 552,
		c_noCDDialogueUnused2 = 553,

		c_gasCtlDescription = 555,
		c_medCtlDescription = 556,
		c_infoCtlDescription = 557,
		c_boatCtlDescription = 558,
		c_copCtlDescription = 559,
		c_pizzaCtlDescription = 560,
		c_raceCtlDescription = 561,

		c_leaveInfoCenterDialogue1 = 562,
		c_leaveInfoCenterDialogue2 = 563,
		c_leaveInfoCenterDialogue3 = 564,
		c_leaveInfoCenterDialogue4 = 565,

		c_unk566 = 566,
		c_unk567 = 567,
		c_unk568 = 568,

		c_unk569 = 569,
		c_unk570 = 570,
		c_unk571 = 571,
		c_unk572 = 572,

		c_registerToContinueDialogue = 573,

		c_bricksterDialogue = 574,
		c_bricksterLaughs = 575,
	};

	enum SndAmimScript {
		c_bookWig = 400
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

	void PlayAction(InfomainScript p_objectId);
	void StopCurrentAction();

	void PlayBookAnimation();
	void StopBookAnimation();

	InfomainScript m_currentInfomainScript; // 0xf8
	MxS16 m_selectedCharacter;              // 0xfc
	InfocenterState* m_infocenterState;     // 0x100
	undefined4 m_transitionDestination;     // 0x104
	Cutscene m_currentCutscene;             // 0x108
	Radio m_radio;                          // 0x10c
	MxStillPresenter* m_unk0x11c;           // 0x11c
	InfocenterMapEntry m_mapAreas[7];       // 0x120
	MxS16 m_unk0x1c8;                       // 0x1c8
	MxStillPresenter* m_frameHotBitmap;     // 0x1cc
	MxS16 m_infoManDialogueTimer;           // 0x1d0
	MxS16 m_bookAnimationTimer;             // 0x1d2
	MxU16 m_unk0x1d4;                       // 0x1d4
	MxS16 m_unk0x1d6;                       // 0x1d6
};

#endif // INFOCENTER_H
