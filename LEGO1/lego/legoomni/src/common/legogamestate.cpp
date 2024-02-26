#include "legogamestate.h"

#include "act1state.h"
#include "define.h"
#include "infocenterstate.h"
#include "islepathactor.h"
#include "legoanimationmanager.h"
#include "legonavcontroller.h"
#include "legoomni.h"
#include "legostate.h"
#include "legounksavedatawriter.h"
#include "legoutil.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "mxbackgroundaudiomanager.h"
#include "mxobjectfactory.h"
#include "mxstring.h"
#include "mxvariabletable.h"
#include "roi/legoroi.h"

#include <stdio.h>

DECOMP_SIZE_ASSERT(LegoGameState::Username, 0xe)
DECOMP_SIZE_ASSERT(LegoGameState::ScoreItem, 0x2c)
DECOMP_SIZE_ASSERT(LegoGameState::History, 0x374)
DECOMP_SIZE_ASSERT(LegoGameState, 0x430)

// GLOBAL: LEGO1 0x100f3e40
// STRING: LEGO1 0x100f3e3c
const char* g_fileExtensionGS = ".GS";

// GLOBAL: LEGO1 0x100f3e44
// STRING: LEGO1 0x100f3e30
const char* g_playersGSI = "Players.gsi";

// GLOBAL: LEGO1 0x100f3e48
// STRING: LEGO1 0x100f3e24
const char* g_historyGSI = "History.gsi";

// This is a pointer to the end of the global variable name table, which has
// the text "END_OF_VARIABLES" in it.
// TODO: make g_endOfVariables reference the actual end of the variable array.
// GLOBAL: LEGO1 0x100f3e50
// STRING: LEGO1 0x100f3e00
const char* g_endOfVariables = "END_OF_VARIABLES";

// GLOBAL: LEGO1 0x100f3e58
ColorStringStruct g_colorSaveData[43] = {
	{"c_dbbkfny0", "lego red"},    {"c_dbbkxly0", "lego white"}, // dunebuggy back fender, dunebuggy back axle
	{"c_chbasey0", "lego black"},  {"c_chbacky0", "lego black"}, // copter base, copter back
	{"c_chdishy0", "lego white"},  {"c_chhorny0", "lego black"}, // copter dish, copter horn
	{"c_chljety1", "lego black"},  {"c_chrjety1", "lego black"}, // copter left jet, copter right jet
	{"c_chmidly0", "lego black"},  {"c_chmotry0", "lego blue"},  // copter middle, copter motor
	{"c_chsidly0", "lego black"},  {"c_chsidry0", "lego black"}, // copter side left, copter side right
	{"c_chstuty0", "lego black"},  {"c_chtaily0", "lego black"}, // copter ???, copter tail
	{"c_chwindy1", "lego black"},  {"c_dbfbrdy0", "lego red"},   // copter ???, dunebuggy ???
	{"c_dbflagy0", "lego yellow"}, {"c_dbfrfny4", "lego red"},   // dunebuggy flag, dunebuggy front fender
	{"c_dbfrxly0", "lego white"},  {"c_dbhndly0", "lego white"}, // dunebuggy front axle, dunebuggy handlebar
	{"c_dbltbry0", "lego white"},  {"c_jsdashy0", "lego white"}, // dunebuggy ???,  jetski dash
	{"c_jsexhy0", "lego black"},   {"c_jsfrnty5", "lego black"}, // jetski exhaust, jetski front
	{"c_jshndly0", "lego red"},    {"c_jslsidy0", "lego black"}, // jetski handlebar, jetski left side
	{"c_jsrsidy0", "lego black"},  {"c_jsskiby0", "lego red"},   // jetski right side, jetski ???
	{"c_jswnshy5", "lego white"},  {"c_rcbacky6", "lego green"}, // jetski windshield, racecar back
	{"c_rcedgey0", "lego green"},  {"c_rcfrmey0", "lego red"},   // racecar edge, racecar frame
	{"c_rcfrnty6", "lego green"},  {"c_rcmotry0", "lego white"}, // racecar front, racecar motor
	{"c_rcsidey0", "lego green"},  {"c_rcstery0", "lego white"}, // racecar side, racecar steering wheel
	{"c_rcstrpy0", "lego yellow"}, {"c_rctailya", "lego white"}, // racecar stripe, racecar tail
	{"c_rcwhl1y0", "lego white"},  {"c_rcwhl2y0", "lego white"}, // racecar wheels 1, racecar wheels 2
	{"c_jsbasey0", "lego white"},  {"c_chblady0", "lego black"}, // jetski base, copter blades
	{"c_chseaty0", "lego white"},                                // copter seat
};

// NOTE: This offset = the end of the variables table, the last entry
// in that table is a special entry, the string "END_OF_VARIABLES"
extern const char* g_endOfVariables;

// FUNCTION: LEGO1 0x10039550
LegoGameState::LegoGameState()
{
	SetColors();
	SetROIHandlerFunction();

	m_stateCount = 0;
	m_actorId = 0;
	m_savePath = NULL;
	m_stateArray = NULL;
	m_unk0x41c = -1;
	m_currentArea = e_noArea;
	m_previousArea = e_noArea;
	m_unk0x42c = e_noArea;
	m_unk0x26 = 0;
	m_isDirty = FALSE;
	m_loadedAct = e_actNotFound;
	SetCurrentAct(e_act1);

	m_backgroundColor = new LegoBackgroundColor("backgroundcolor", "set 56 54 68");
	VariableTable()->SetVariable(m_backgroundColor);

	m_tempBackgroundColor = new LegoBackgroundColor("tempBackgroundColor", "set 56 54 68");
	VariableTable()->SetVariable(m_tempBackgroundColor);

	m_fullScreenMovie = new LegoFullScreenMovie("fsmovie", "disable");
	VariableTable()->SetVariable(m_fullScreenMovie);

	VariableTable()->SetVariable("lightposition", "2");
	SerializeScoreHistory(1);
}

// FUNCTION: LEGO1 0x10039720
LegoGameState::~LegoGameState()
{
	LegoROI::SetSomeHandlerFunction(NULL);

	if (m_stateCount) {
		for (MxS16 i = 0; i < m_stateCount; i++) {
			LegoState* state = m_stateArray[i];
			if (state) {
				delete state;
			}
		}

		delete[] m_stateArray;
	}

	delete[] m_savePath;
}

// FUNCTION: LEGO1 0x10039780
void LegoGameState::SetActor(MxU8 p_actorId)
{
	if (p_actorId) {
		m_actorId = p_actorId;
	}

	IslePathActor* oldActor = CurrentActor();
	SetCurrentActor(NULL);

	IslePathActor* newActor = new IslePathActor();
	const char* actorName = LegoActor::GetActorName(m_actorId);
	LegoROI* roi = UnkSaveDataWriter()->FUN_10083500(actorName, FALSE);
	MxDSAction action;

	action.SetAtomId(*g_isleScript);
	action.SetObjectId(100000);
	newActor->Create(action);
	newActor->SetActorId(p_actorId);
	newActor->SetROI(roi, FALSE, FALSE);

	if (oldActor) {
		newActor->GetROI()->FUN_100a58f0(oldActor->GetROI()->GetLocal2World());
		newActor->SetUnknown88(oldActor->GetUnknown88());
		delete oldActor;
	}

	newActor->ClearFlag(0x02);
	SetCurrentActor(newActor);
}

// STUB: LEGO1 0x10039940
void LegoGameState::FUN_10039940()
{
	// TODO
}

// FUNCTION: LEGO1 0x10039980
MxResult LegoGameState::Save(MxULong p_slot)
{
	MxResult result;
	InfocenterState* infocenterState = (InfocenterState*) GameState()->GetState("InfocenterState");

	if (!infocenterState || !infocenterState->HasRegistered()) {
		result = SUCCESS;
	}
	else {
		result = FAILURE;
		MxVariableTable* variableTable = VariableTable();
		MxString savePath;
		GetFileSavePath(&savePath, p_slot);
		LegoFile fileStream;
		if (fileStream.Open(savePath.GetData(), LegoFile::c_write) != FAILURE) {
			MxU32 maybeVersion = 0x1000C;
			fileStream.Write(&maybeVersion, 4);
			fileStream.Write(&m_unk0x24, 2);
			fileStream.Write(&m_currentAct, 2);
			fileStream.Write(&m_actorId, 1);

			for (MxS32 i = 0; i < sizeof(g_colorSaveData) / sizeof(g_colorSaveData[0]); ++i) {
				if (WriteVariable(&fileStream, variableTable, g_colorSaveData[i].m_targetName) == FAILURE) {
					return result;
				}
			}

			if (WriteVariable(&fileStream, variableTable, "backgroundcolor") != FAILURE) {
				if (WriteVariable(&fileStream, variableTable, "lightposition") != FAILURE) {
					WriteEndOfVariables(&fileStream);

					// TODO: Calls down to more aggregate writing functions
					return SUCCESS;
				}
			}
		}
	}
	return result;
}

// STUB: LEGO1 0x10039c60
MxResult LegoGameState::Load(MxULong)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10039f00
void LegoGameState::SetSavePath(char* p_savePath)
{
	if (m_savePath != NULL) {
		delete[] m_savePath;
	}

	if (p_savePath) {
		m_savePath = new char[strlen(p_savePath) + 1];
		strcpy(m_savePath, p_savePath);
	}
	else {
		m_savePath = NULL;
	}
}

// FUNCTION: LEGO1 0x10039f70
MxResult LegoGameState::WriteVariable(LegoStorage* p_storage, MxVariableTable* p_from, const char* p_variableName)
{
	MxResult result = FAILURE;
	const char* variableValue = p_from->GetVariable(p_variableName);

	if (variableValue) {
		MxU8 length = strlen(p_variableName);
		if (p_storage->Write((char*) &length, 1) == SUCCESS) {
			if (p_storage->Write(p_variableName, length) == SUCCESS) {
				length = strlen(variableValue);
				if (p_storage->Write((char*) &length, 1) == SUCCESS) {
					result = p_storage->Write((char*) variableValue, length);
				}
			}
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1003a020
MxResult LegoGameState::WriteEndOfVariables(LegoStorage* p_storage)
{
	MxU8 len = strlen(g_endOfVariables);

	if (p_storage->Write(&len, 1) == SUCCESS) {
		return p_storage->Write(g_endOfVariables, len);
	}

	return FAILURE;
}

// 95% match, just some instruction ordering differences on the call to
// MxVariableTable::SetVariable at the end.
// FUNCTION: LEGO1 0x1003a080
MxS32 LegoGameState::ReadVariable(LegoStorage* p_storage, MxVariableTable* p_to)
{
	MxS32 result = 1;
	MxU8 length;

	if (p_storage->Read((char*) &length, 1) == SUCCESS) {
		char nameBuffer[256];
		if (p_storage->Read(nameBuffer, length) == SUCCESS) {
			nameBuffer[length] = '\0';
			if (strcmp(nameBuffer, g_endOfVariables) == 0) {
				// 2 -> "This was the last entry, done reading."
				result = 2;
			}
			else {
				if (p_storage->Read((char*) &length, 1) == SUCCESS) {
					char valueBuffer[256];
					if (p_storage->Read(valueBuffer, length) == SUCCESS) {
						result = 0;
						valueBuffer[length] = '\0';
						p_to->SetVariable(nameBuffer, valueBuffer);
					}
				}
			}
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1003a170
void LegoGameState::GetFileSavePath(MxString* p_outPath, MxULong p_slotn)
{
	char baseForSlot[2] = "0";
	char path[1024] = "";

	// Save path base
	if (m_savePath != NULL) {
		strcpy(path, m_savePath);
	}

	// Slot: "G0", "G1", ...
	strcat(path, "\\G");
	baseForSlot[0] += p_slotn;
	strcat(path, baseForSlot);

	// Extension: ".GS"
	strcat(path, g_fileExtensionGS);
	*p_outPath = MxString(path);
}

// STUB: LEGO1 0x1003a2e0
void LegoGameState::SerializePlayersInfo(MxS16)
{
	// TODO
}

// FUNCTION: LEGO1 0x1003a720
void LegoGameState::StopArea(Area p_area)
{
	if (p_area == e_previousArea) {
		p_area = m_previousArea;
	}

	switch (p_area) {
	case e_isle:
		InvokeAction(Extra::e_stop, *g_isleScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_isleScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_sndAnimScript, 0, NULL);
		break;
	case e_infomain:
		InvokeAction(Extra::e_stop, *g_infomainScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_infomainScript, 0, NULL);
		break;
	case e_infodoor:
		InvokeAction(Extra::e_stop, *g_infodoorScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_infodoorScript, 0, NULL);
		break;
	case e_elevbott:
		InvokeAction(Extra::e_stop, *g_elevbottScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_elevbottScript, 0, NULL);
		break;
	case e_elevride:
	case e_elevride2:
		RemoveFromWorld(*g_isleScript, 0x41b, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 1052, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x41d, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x41e, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x420, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x422, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x424, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x426, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x428, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x42a, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x42b, *g_isleScript, 0);
		break;
	case e_elevopen:
		RemoveFromWorld(*g_isleScript, 0x45b, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x45c, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x45d, *g_isleScript, 0);
		break;
	case e_seaview:
		RemoveFromWorld(*g_isleScript, 0x475, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x476, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x477, *g_isleScript, 0);
		break;
	case e_observe:
		RemoveFromWorld(*g_isleScript, 0x45f, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x460, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x461, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x462, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x463, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x464, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x465, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x466, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x467, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x469, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x468, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x46a, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x46b, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x46c, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x46d, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x46e, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x46f, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x471, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x472, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x12, *g_isleScript, 0);
		break;
	case e_elevdown:
		RemoveFromWorld(*g_isleScript, 0x47a, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x47b, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x47c, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x47d, *g_isleScript, 0);
		break;
	case e_regbook:
		InvokeAction(Extra::e_stop, *g_regbookScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_regbookScript, 0, NULL);
		break;
	case e_infoscor:
		InvokeAction(Extra::e_stop, *g_infoscorScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_infoscorScript, 0, NULL);
		break;
	case e_jetrace:
		InvokeAction(Extra::e_stop, *g_jetraceScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_jetraceScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_jetracerScript, 0, NULL);
		break;
	case e_carrace:
		InvokeAction(Extra::e_stop, *g_carraceScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_carraceScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_carracerScript, 0, NULL);
		break;
	case e_garage:
		Lego()->RemoveWorld(*g_garageScript, 0);
		InvokeAction(Extra::e_stop, *g_garageScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_garageScript, 0, NULL);
		break;
	case e_garadoor:
		RemoveFromWorld(*g_isleScript, 0x489, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x48a, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x48b, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x48c, *g_isleScript, 0);
		break;
	case e_hospital:
		InvokeAction(Extra::e_stop, *g_hospitalScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_hospitalScript, 0, NULL);
		break;
	case e_police:
		InvokeAction(Extra::e_stop, *g_policeScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_policeScript, 0, NULL);
		break;
	case e_polidoor:
		RemoveFromWorld(*g_isleScript, 0x47f, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x480, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x481, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x482, *g_isleScript, 0);
		break;
	case e_copter:
		InvokeAction(Extra::e_stop, *g_jukeboxScript, 0x2f, NULL);
		InvokeAction(Extra::e_stop, *g_copterScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_copterScript, 0, NULL);
		break;
	case e_dunecar:
		InvokeAction(Extra::e_stop, *g_jukeboxScript, 0x31, NULL);
		InvokeAction(Extra::e_stop, *g_dunecarScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_dunecarScript, 0, NULL);
		break;
	case e_jetski:
		InvokeAction(Extra::e_stop, *g_jukeboxScript, 0x33, NULL);
		InvokeAction(Extra::e_stop, *g_jetskiScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_jetskiScript, 0, NULL);
		break;
	case e_racecar:
		InvokeAction(Extra::e_stop, *g_jukeboxScript, 0x35, NULL);
		InvokeAction(Extra::e_stop, *g_racecarScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_racecarScript, 0, NULL);
		break;
	case e_act2main:
		if (m_currentArea != 2) {
			InvokeAction(Extra::e_stop, *g_act2mainScript, 0, NULL);
			InvokeAction(Extra::e_close, *g_act2mainScript, 0, NULL);
		}
		break;
	case e_act3script:
		if (m_currentArea != 2) {
			InvokeAction(Extra::e_stop, *g_act3Script, 0, NULL);
			InvokeAction(Extra::e_close, *g_act3Script, 0, NULL);
		}
		break;
	case e_jukeboxw:
		InvokeAction(Extra::e_stop, *g_jukeboxwScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_jukeboxwScript, 0, NULL);
		break;
	case e_histbook:
		InvokeAction(Extra::e_disable, *g_histbookScript, 0, NULL);
		InvokeAction(Extra::e_stop, *g_histbookScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_histbookScript, 0, NULL);
		break;
	}
}

inline void LoadIsle()
{
	LegoWorld* world = FindWorld(*g_isleScript, 0);
	if (world != NULL) {
		if (!world->GetUnknown0xd0().empty()) {
#ifdef COMPAT_MODE
			{
				MxNotificationParam param(c_notificationType20, NULL);
				NotificationManager()->Send(world, &param);
			}
#else
			NotificationManager()->Send(world, &MxNotificationParam(c_notificationType20, NULL));
#endif
		}
	}
	else {
		InvokeAction(Extra::ActionType::e_opendisk, *g_isleScript, 0, NULL);
	}
}

// FUNCTION: LEGO1 0x1003b060
void LegoGameState::SwitchArea(Area p_area)
{
	m_previousArea = m_currentArea;
	m_currentArea = p_area;

	FUN_10015820(TRUE, LegoOmni::c_disableInput | LegoOmni::c_disable3d);
	BackgroundAudioManager()->Stop();
	AnimationManager()->FUN_1005ef10();
	VideoManager()->SetUnk0x554(FALSE);

	switch (p_area) {
	case e_isle:
		InvokeAction(Extra::ActionType::e_opendisk, *g_isleScript, 0, NULL);
		break;
	case e_infomain:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_infomainScript, 0, NULL);
		break;
	case e_infodoor:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_infodoorScript, 0, NULL);
		break;
	case e_unk4:
	case e_jetrace2:
	case e_jetraceExterior:
	case e_unk17:
	case e_carraceExterior:
	case e_unk20:
	case e_unk21:
	case e_pizzeriaExterior:
	case e_garageExterior:
	case e_hospitalExterior:
	case e_unk31:
	case e_policeExterior:
	case e_unk57:
	case e_unk58:
	case e_unk59:
	case e_unk60:
	case e_unk61:
	case e_unk64:
	case e_unk66:
		LoadIsle();
		break;
	case e_elevbott:
		InvokeAction(Extra::ActionType::e_opendisk, *g_elevbottScript, 0, NULL);
		break;
	case e_elevride:
	case e_elevride2:
		LoadIsle();
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, 1050, NULL);
		break;
	case e_elevopen:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, 1114, NULL);
		break;
	case e_seaview:
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, 1140, NULL);
		break;
	case e_observe:
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, 1118, NULL);
		break;
	case e_elevdown:
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, 1145, NULL);
		break;
	case e_regbook:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_regbookScript, 0, NULL);
		break;
	case e_infoscor:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_infoscorScript, 0, NULL);
		break;
	case e_jetrace:
		if (m_previousArea == e_infomain) {
			m_currentArea = e_jetrace2;
			LoadIsle();
		}
		else {
			InvokeAction(Extra::ActionType::e_opendisk, *g_jetraceScript, 0, NULL);
		}
		break;
	case e_carrace:
		if (m_previousArea == e_infomain) {
			m_currentArea = e_carraceExterior;
			LoadIsle();
		}
		else {
			InvokeAction(Extra::ActionType::e_opendisk, *g_carraceScript, 0, NULL);
		}
		break;
	case e_garage:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_garageScript, 0, NULL);
		break;
	case e_garadoor:
		LoadIsle();
		VariableTable()->SetVariable("VISIBILITY", "Hide Gas");
		CurrentActor()->ResetWorldTransform(FALSE);
		NavController()->SetLocation(0x3b);
		VideoManager()->Get3DManager()->SetFrustrum(90, 0.1f, 250.0f);
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, 1160, NULL);
		break;
	case e_unk28: {
		Act1State* state = (Act1State*) GameState()->GetState("Act1State");
		LoadIsle();
		if (state->GetUnknown18() == 7) {
			VideoManager()->Get3DManager()->SetFrustrum(90, 0.1f, 250.0f);
		}
		else {
			SetCameraControllerFromIsle();
			CurrentActor()->ResetWorldTransform(TRUE);
			AnimationManager()->FUN_1005f0b0();
		}
		CurrentActor()->VTable0xe8(p_area, TRUE, 7);
		break;
	}
	case e_hospital:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_hospitalScript, 0, NULL);
		break;
	case e_unk33:
		LoadIsle();
		SetCameraControllerFromIsle();
		CurrentActor()->ResetWorldTransform(TRUE);
		AnimationManager()->FUN_1005f0b0();
		CurrentActor()->VTable0xe8(p_area, TRUE, 7);
		break;
	case e_police:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_policeScript, 0, NULL);
		break;
	case e_polidoor:
		LoadIsle();
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, 1150, NULL);
		break;
	case e_copter:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_copterScript, 0, NULL);
		break;
	case e_dunecar:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_dunecarScript, 0, NULL);
		break;
	case e_jetski:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_jetskiScript, 0, NULL);
		break;
	case e_racecar:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_racecarScript, 0, NULL);
		break;
	case e_act2main: {
		LegoWorld* act2main = FindWorld(*g_act2mainScript, 0);
		if (act2main == NULL) {
			InvokeAction(Extra::ActionType::e_opendisk, *g_act2mainScript, 0, NULL);
		}
		else {
			act2main->Enable(TRUE);
		}
		break;
	}
	case e_act3script: {
		LegoWorld* act3 = FindWorld(*g_act3Script, 0);
		if (act3 == NULL) {
			InvokeAction(Extra::ActionType::e_opendisk, *g_act3Script, 0, NULL);
		}
		else {
			act3->Enable(TRUE);
		}
		break;
	}
	case e_jukeboxw:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_jukeboxwScript, 0, NULL);
		break;
	case e_unk54:
		LoadIsle();
		break;
	case e_histbook:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_histbookScript, 0, NULL);
		break;
	default:
		break;
	}
}

// FUNCTION: LEGO1 0x1003ba90
void LegoGameState::SetColors()
{
	MxVariableTable* variableTable = VariableTable();

	for (MxS32 i = 0; i < _countof(g_colorSaveData); i++) {
		variableTable->SetVariable(g_colorSaveData[i].m_targetName, g_colorSaveData[i].m_colorName);
	}
}

// FUNCTION: LEGO1 0x1003bac0
void LegoGameState::SetROIHandlerFunction()
{
	LegoROI::SetSomeHandlerFunction(&ROIHandlerFunction);
}

// FUNCTION: LEGO1 0x1003bad0
MxBool ROIHandlerFunction(char* p_input, char* p_output, MxU32 p_copyLen)
{
	if (p_output != NULL && p_copyLen != 0 &&
		(strnicmp(p_input, "INDIR-F-", strlen("INDIR-F-")) == 0 ||
		 strnicmp(p_input, "INDIR-G-", strlen("INDIR-F-")) == 0)) {

		char buf[256];
		sprintf(buf, "c_%s", &p_input[strlen("INDIR-F-")]);

		const char* value = VariableTable()->GetVariable(buf);
		if (value != NULL) {
			strncpy(p_output, value, p_copyLen);
			p_output[p_copyLen - 1] = '\0';
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x1003bbb0
LegoState* LegoGameState::GetState(const char* p_stateName)
{
	for (MxS32 i = 0; i < m_stateCount; ++i) {
		if (m_stateArray[i]->IsA(p_stateName)) {
			return m_stateArray[i];
		}
	}
	return NULL;
}

// FUNCTION: LEGO1 0x1003bc00
LegoState* LegoGameState::CreateState(const char* p_stateName)
{
	LegoState* newState = (LegoState*) ObjectFactory()->Create(p_stateName);
	RegisterState(newState);

	return newState;
}

// FUNCTION: LEGO1 0x1003bc30
void LegoGameState::RegisterState(LegoState* p_state)
{
	MxS32 targetIndex;
	for (targetIndex = 0; targetIndex < m_stateCount; ++targetIndex) {
		if (m_stateArray[targetIndex]->IsA(p_state->ClassName())) {
			break;
		}
	}

	if (targetIndex == m_stateCount) {
		LegoState** newBuffer = new LegoState*[m_stateCount + 1];

		if (m_stateCount != 0) {
			memcpy(newBuffer, m_stateArray, m_stateCount * sizeof(LegoState*));
			delete[] m_stateArray;
		}

		newBuffer[m_stateCount++] = p_state;
		m_stateArray = newBuffer;
		return;
	}

	if (m_stateArray[targetIndex]) {
		delete m_stateArray[targetIndex];
	}
	m_stateArray[targetIndex] = p_state;
}

// FUNCTION: LEGO1 0x1003c670
LegoGameState::Username::Username()
{
	memset(m_letters, -1, sizeof(m_letters));
}

// FUNCTION: LEGO1 0x1003c690
MxResult LegoGameState::Username::ReadWrite(LegoStorage* p_storage)
{
	if (p_storage->IsReadMode()) {
		for (MxS16 i = 0; i < 7; i++) {
			p_storage->Read(&m_letters[i], sizeof(m_letters[i]));
		}
	}
	else if (p_storage->IsWriteMode()) {
		for (MxS16 i = 0; i < 7; i++) {
			MxS16 letter = m_letters[i];
			p_storage->Write(&letter, sizeof(letter));
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1003c710
LegoGameState::Username* LegoGameState::Username::operator=(const Username* p_other)
{
	memcpy(m_letters, p_other->m_letters, sizeof(m_letters));
	return this;
}

// FUNCTION: LEGO1 0x1003c830
LegoGameState::History::History()
{
	m_count = 0;
	m_unk0x372 = 0;
}

// STUB: LEGO1 0x1003c870
void LegoGameState::History::WriteScoreHistory()
{
	// TODO
}

// STUB: LEGO1 0x1003ccf0
void LegoGameState::History::FUN_1003ccf0(LegoFile&)
{
	// TODO
}

// FUNCTION: LEGO1 0x1003cdd0
void LegoGameState::SerializeScoreHistory(MxS16 p_flags)
{
	LegoFile stream;
	MxString savePath(m_savePath);
	savePath += "\\";
	savePath += g_historyGSI;

	if (p_flags == LegoFile::c_write) {
		m_history.WriteScoreHistory();
	}

	if (stream.Open(savePath.GetData(), p_flags) == SUCCESS) {
		m_history.FUN_1003ccf0(stream);
	}
}

// FUNCTION: LEGO1 0x1003cea0
void LegoGameState::SetCurrentAct(Act p_currentAct)
{
	m_currentAct = p_currentAct;
}

// FUNCTION: LEGO1 0x1003ceb0
void LegoGameState::FindLoadedAct()
{
	if (FindWorld(*g_isleScript, 0)) {
		m_loadedAct = e_act1;
	}
	else if (FindWorld(*g_act2mainScript, 0)) {
		m_loadedAct = e_act2;
	}
	else if (FindWorld(*g_act3Script, 0)) {
		m_loadedAct = e_act3;
	}
	else {
		m_loadedAct = e_actNotFound;
	}
}
