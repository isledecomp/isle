#include "radiostate.h"

#include "jukebox.h"
#include "legoomni.h"
#include "mxmisc.h"
#include "mxtimer.h"

// GLOBAL: LEGO1 0x100f3218
JukeBox::JukeBoxScript g_unk0x100f3218[6] = {
	JukeBox::e_legoRadioReminder1,
	JukeBox::e_legoRadioJingle1,
	JukeBox::e_legoRadioJingle2,
	JukeBox::e_legoRadioJingle3,
	JukeBox::e_legoRadioJingle4,
	JukeBox::e_legoRadioReminder2
};

// GLOBAL: LEGO1 0x100f3230
JukeBox::JukeBoxScript g_unk0x100f3230[14] = {
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
JukeBox::JukeBoxScript g_unk0x100f3268[9] = {
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

	m_unk0x08[0] = LegoState::Playlist((MxU32*) g_unk0x100f3218, sizeof(g_unk0x100f3218) / sizeof(g_unk0x100f3218[0]));
	m_unk0x08[0].SetUnknown0x08(rand() % (sizeof(g_unk0x100f3218) / sizeof(g_unk0x100f3218[0])));

	m_unk0x08[1] = LegoState::Playlist((MxU32*) g_unk0x100f3230, sizeof(g_unk0x100f3230) / sizeof(g_unk0x100f3230[0]));
	m_unk0x08[1].SetUnknown0x08(rand() % (sizeof(g_unk0x100f3230) / sizeof(g_unk0x100f3230[0])));

	m_unk0x08[2] = LegoState::Playlist((MxU32*) g_unk0x100f3268, sizeof(g_unk0x100f3268) / sizeof(g_unk0x100f3268[0]));
	m_unk0x08[2].SetUnknown0x08(rand() % (sizeof(g_unk0x100f3268) / sizeof(g_unk0x100f3268[0])));

	m_active = FALSE;
}

// FUNCTION: LEGO1 0x1002cf50
MxBool RadioState::VTable0x14()
{
	return FALSE;
}

// FUNCTION: LEGO1 0x1002d090
MxU32 RadioState::FUN_1002d090()
{
	if (m_unk0x2c == 2) {
		m_unk0x2c = 0;
	}
	else {
		m_unk0x2c++;
	}

	return m_unk0x08[m_unk0x2c].Next();
}

// FUNCTION: LEGO1 0x1002d0c0
MxBool RadioState::FUN_1002d0c0(const MxAtomId& p_atom, MxU32 p_objectId)
{
	if (*g_jukeboxScript == p_atom) {
		for (MxS16 i = 0; i < 3; i++) {
			if (m_unk0x08[i].Contains(p_objectId)) {
				return TRUE;
			}
		}
	}

	return FALSE;
}
