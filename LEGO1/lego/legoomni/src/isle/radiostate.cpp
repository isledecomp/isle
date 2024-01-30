#include "radiostate.h"

#include "jukebox.h"
#include "legoomni.h"
#include "mxtimer.h"

// GLOBAL: LEGO1 0x100f3218
JukeBox::JukeBoxScript m_unk0x100f3218[6] = {
	JukeBox::e_legoRadioReminder1,
	JukeBox::e_legoRadioJingle1,
	JukeBox::e_legoRadioJingle2,
	JukeBox::e_legoRadioJingle3,
	JukeBox::e_legoRadioJingle4,
	JukeBox::e_legoRadioReminder2
};

// GLOBAL: LEGO1 0x100f3230
JukeBox::JukeBoxScript m_unk0x100f3230[14] = {
	JukeBox::e_legoRadioRacingAd,
	JukeBox::e_legoRadioNews1,
	JukeBox::e_legoRadioNews2,
	JukeBox::e_legoRadioPizzaAd1,
	JukeBox::e_legoRadioBricksterPSA,
	JukeBox::e_legoRadioSports1,
	JukeBox::e_legoRadioIntermission1,
	JukeBox::e_legoRadioIntermission2,
	JukeBox::e_legoRadioPizzaAd2,
	JukeBox::e_legoRadioWeatherReport,
	JukeBox::e_legoRadioSports2,
	JukeBox::e_legoRadioPizzaAd3,
	JukeBox::e_legoRadioIntermission3,
	JukeBox::e_legoRadioSuperStoreAd,
};

// GLOBAL: LEGO1 0x100f3268
JukeBox::JukeBoxScript m_unk0x100f3268[9] = {
	JukeBox::e_centralRoads,
	JukeBox::e_beachBlvd,
	JukeBox::e_residentialArea,
	JukeBox::e_legoRadioLuckyYou,
	JukeBox::e_legoRadioJazzInterlude,
	JukeBox::e_legoRadioPianoInterlude1,
	JukeBox::e_legoRadioPoliceStation,
	JukeBox::e_legoRadioPianoInterlude2,
	JukeBox::e_legoRadioCredits,
};

// FUNCTION: LEGO1 0x1002ce10
RadioState::RadioState()
{
	srand(Timer()->GetTime());

	MxS32 random = rand();
	m_unk0x2c = random % 3;

	m_unk0x08[0].m_unk0x08 = 0;
	m_unk0x08[0].m_unk0x06 = 0;
	m_unk0x08[0].m_unk0x04 = 6;
	m_unk0x08[0].m_unk0x00 = m_unk0x100f3218;

	random = rand();

	m_unk0x08[1].m_unk0x08 = 0;
	m_unk0x08[1].m_unk0x06 = 0;
	m_unk0x08[1].m_unk0x04 = 14;
	m_unk0x08[1].m_unk0x00 = m_unk0x100f3230;

	m_unk0x08[0].m_unk0x08 = (MxU32) random % 6;
	random = rand();

	m_unk0x08[2].m_unk0x08 = 0;
	m_unk0x08[2].m_unk0x06 = 0;
	m_unk0x08[2].m_unk0x04 = 9;
	m_unk0x08[2].m_unk0x00 = m_unk0x100f3268;

	m_unk0x08[1].m_unk0x08 = (MxU32) random % 14;
	random = rand();

	m_unk0x08[2].m_unk0x08 = (MxU32) random % 9;

	m_unk0x2e = 0;
}

// STUB: LEGO1 0x1002cf50
MxBool RadioState::VTable0x14()
{
	// TODO
	return FALSE;
}
