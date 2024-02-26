#ifndef JUKEBOX_H
#define JUKEBOX_H

#include "decomp.h"
#include "jukeboxstate.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoworld.h"

// VTABLE: LEGO1 0x100d8958
// SIZE 0x104
class JukeBox : public LegoWorld {
public:
	// JUKEBOXW.SI
	enum JukeBoxWorldScript {
		c_volDownCtl = 1,
		c_volUpCtl = 2,
		c_dBackCtl = 3,
		c_dFwdCtl = 4,
		c_noteCtl = 5
	};

	// JUKEBOX.SI (the actual audio)
	enum JukeBoxScript {
		e_mamaPapaBrickolini,
		e_jailUnused,
		e_act2Cave,
		e_bricksterChase,
		e_brickHunt,
		e_residentialArea,
		e_beachBlvd,
		e_cave,
		e_centralRoads,
		e_jail,
		e_hospital,
		e_informationCenter,
		e_policeStation,
		e_park,
		e_centralNorthRoad,
		e_garageArea,
		e_raceTrack,
		e_beach,
		e_quietChirping,
		e_jetskiRace,
		e_act3Pursuit,

		e_legoRadioReminder1,
		e_legoRadioJingle1,
		e_legoRadioJingle2,
		e_legoRadioJingle3,
		e_legoRadioJingle4,
		e_legoRadioReminder2,

		e_legoRadioRacingAd,
		e_legoRadioNews1,
		e_legoRadioNews2,
		e_legoRadioPizzaAd1,
		e_legoRadioBricksterPSA,
		e_legoRadioSports1,
		e_legoRadioIntermission1,
		e_legoRadioIntermission2,
		e_legoRadioPizzaAd2,
		e_legoRadioWeatherReport,
		e_legoRadioSports2,
		e_legoRadioPizzaAd3,
		e_legoRadioIntermission3,
		e_legoRadioSuperStoreAd,

		e_legoRadioLuckyYou,
		e_legoRadioJazzInterlude,
		e_legoRadioPianoInterlude1,
		e_legoRadioPoliceStation,
		e_legoRadioPianoInterlude2,
		e_legoRadioCredits,

		e_helicopterBuild,
		e_padding1,
		e_duneBuggyBuild,
		e_padding2,
		e_jetskiBuild,
		e_padding3,
		e_raceCarBuild,
		e_padding4,

		e_jukeBoxMamaPapaBrickolini,
		e_jukeBoxBrickByBrick,
		e_jukeBoxTheBrickster,
		e_jukeBoxBuildMeABridgeToday,
		e_jukeBoxBaroqueInBrick,
		e_jukeBoxMantaRay,

		e_observationDeck,
		e_elevator,
		e_pizzaMission,
	};

	JukeBox();
	~JukeBox() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x1005d6f0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f02cc
		return "JukeBox";
	}

	// FUNCTION: LEGO1 0x1005d700
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, JukeBox::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x5c() override;                     // vtable+0x5c
	MxBool VTable0x64() override;                     // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	// SYNTHETIC: LEGO1 0x1005d810
	// JukeBox::`scalar deleting destructor'

private:
	MxBool HandleClick(LegoControlManagerEvent& p_param);

	LegoGameState::Area m_transitionDestination; // 0xf8
	JukeBoxState* m_state;                       // 0xfc
	undefined2 m_unk0x100;                       // 0x100
};

#endif // JUKEBOX_H
