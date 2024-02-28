#include "legogamestate.h"

#include "act1state.h"
#include "define.h"
#include "dunebuggy.h"
#include "helicopter.h"
#include "infocenterstate.h"
#include "isle.h"
#include "islepathactor.h"
#include "jetski.h"
#include "legoanimationmanager.h"
#include "legobuildingmanager.h"
#include "legonavcontroller.h"
#include "legoomni.h"
#include "legoplantmanager.h"
#include "legostate.h"
#include "legounksavedatawriter.h"
#include "legoutil.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "mxbackgroundaudiomanager.h"
#include "mxobjectfactory.h"
#include "mxstring.h"
#include "mxvariabletable.h"
#include "racecar.h"
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
	m_playerCount = 0;
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

// FUNCTION: LEGO1 0x10039910
void LegoGameState::RemoveActor()
{
	IslePathActor* actor = CurrentActor();
	SetCurrentActor(NULL);
	delete actor;
	m_actorId = 0;
}

// FUNCTION: LEGO1 0x10039940
void LegoGameState::ResetROI()
{
	if (m_actorId) {
		IslePathActor* actor = CurrentActor();

		if (actor) {
			LegoROI* roi = actor->GetROI();

			if (roi) {
				VideoManager()->Get3DManager()->GetLego3DView()->Remove(*roi);
				VideoManager()->Get3DManager()->GetLego3DView()->Add(*roi);
			}
		}
	}
}

// FUNCTION: LEGO1 0x10039980
MxResult LegoGameState::Save(MxULong p_slot)
{
	InfocenterState* infocenterState = (InfocenterState*) GameState()->GetState("InfocenterState");

	if (!infocenterState || !infocenterState->HasRegistered()) {
		return SUCCESS;
	}

	MxResult result = FAILURE;
	LegoFile fileStorage;
	MxVariableTable* variableTable = VariableTable();
	MxS16 count = 0;
	MxU32 i;
	MxS32 j;
	MxU16 area;

	MxString savePath;
	GetFileSavePath(&savePath, p_slot);

	if (fileStorage.Open(savePath.GetData(), LegoFile::c_write) == FAILURE) {
		goto done;
	}

	Write(&fileStorage, 0x1000c);
	Write(&fileStorage, m_unk0x24);
	Write(&fileStorage, (MxU16) m_currentAct);
	Write(&fileStorage, m_actorId);

	for (i = 0; i < _countof(g_colorSaveData); i++) {
		if (WriteVariable(&fileStorage, variableTable, g_colorSaveData[i].m_targetName) == FAILURE) {
			goto done;
		}
	}

	if (WriteVariable(&fileStorage, variableTable, "backgroundcolor") == FAILURE) {
		goto done;
	}
	if (WriteVariable(&fileStorage, variableTable, "lightposition") == FAILURE) {
		goto done;
	}

	WriteEndOfVariables(&fileStorage);
	UnkSaveDataWriter()->WriteSaveData3(&fileStorage);
	PlantManager()->Save(&fileStorage);
	result = BuildingManager()->Save(&fileStorage);

	for (j = 0; j < m_stateCount; j++) {
		if (m_stateArray[j]->VTable0x14()) {
			count++;
		}
	}

	Write(&fileStorage, count);

	for (j = 0; j < m_stateCount; j++) {
		if (m_stateArray[j]->VTable0x14()) {
			m_stateArray[j]->VTable0x1c(&fileStorage);
		}
	}

	area = m_unk0x42c;
	Write(&fileStorage, (MxU16) area);
	SerializeScoreHistory(2);
	m_isDirty = FALSE;

done:
	return result;
}

// FUNCTION: LEGO1 0x10039bf0
MxResult LegoGameState::DeleteState()
{
	MxS16 stateCount = m_stateCount;
	LegoState** stateArray = m_stateArray;

	m_stateCount = 0;
	m_stateArray = NULL;

	for (MxS32 count = 0; count < stateCount; count++) {
		if (!stateArray[count]->SetFlag() && stateArray[count]->VTable0x14()) {
			delete stateArray[count];
		}
		else {
			RegisterState(stateArray[count]);
			stateArray[count] = NULL;
		}
	}

	delete[] stateArray;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10039c60
MxResult LegoGameState::Load(MxULong p_slot)
{
	MxResult result = FAILURE;
	LegoFile fileStorage;
	MxVariableTable* variableTable = VariableTable();

	MxString savePath;
	GetFileSavePath(&savePath, p_slot);

	if (fileStorage.Open(savePath.GetData(), LegoFile::c_read) == FAILURE) {
		goto done;
	}

	MxU32 version, status;
	MxS16 count, area, act;
	const char* lightPosition;

	Read(&fileStorage, &version);

	if (version != 0x1000c) {
		OmniError("Saved game version mismatch", 0);
		goto done;
	}

	Read(&fileStorage, &m_unk0x24);

	Read(&fileStorage, &act);
	SetCurrentAct((Act) act);

	Read(&fileStorage, &m_actorId);
	if (m_actorId) {
		SetActor(m_actorId);
	}

	do {
		status = ReadVariable(&fileStorage, variableTable);
		if (status == 1) {
			goto done;
		}
	} while (status != 2);

	m_backgroundColor->SetLights();
	lightPosition = VariableTable()->GetVariable("lightposition");

	if (lightPosition) {
		SetLightPosition(atoi(lightPosition));
	}

	if (UnkSaveDataWriter()->ReadSaveData3(&fileStorage) == FAILURE) {
		goto done;
	}
	if (PlantManager()->Load(&fileStorage) == FAILURE) {
		goto done;
	}
	if (BuildingManager()->Load(&fileStorage) == FAILURE) {
		goto done;
	}
	if (DeleteState() != SUCCESS) {
		goto done;
	}

	char stateName[80];
	Read(&fileStorage, &count);

	if (count) {
		for (MxS16 i = 0; i < count; i++) {
			MxS16 stateNameLength;
			Read(&fileStorage, &stateNameLength);
			Read(&fileStorage, stateName, (MxULong) stateNameLength);
			stateName[stateNameLength] = 0;

			LegoState* state = GetState(stateName);
			if (!state) {
				state = CreateState(stateName);

				if (!state) {
					goto done;
				}
			}

			state->VTable0x1c(&fileStorage);
		}
	}

	Read(&fileStorage, &area);

	if (m_currentAct == 0) {
		m_unk0x42c = e_noArea;
	}
	else {
		m_unk0x42c = (Area) area;
	}

	result = SUCCESS;
	m_isDirty = FALSE;

done:
	if (result != SUCCESS) {
		OmniError("Game state loading was not successful!", 0);
	}

	return result;
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
		if (p_storage->Write(&length, sizeof(length)) == SUCCESS) {
			if (p_storage->Write(p_variableName, length) == SUCCESS) {
				length = strlen(variableValue);
				if (p_storage->Write(&length, sizeof(length)) == SUCCESS) {
					result = p_storage->Write(variableValue, length);
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

	if (p_storage->Write(&len, sizeof(len)) == SUCCESS) {
		return p_storage->Write(g_endOfVariables, len);
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x1003a080
MxS32 LegoGameState::ReadVariable(LegoStorage* p_storage, MxVariableTable* p_to)
{
	MxS32 result = 1;
	MxU8 length;

	if (p_storage->Read(&length, sizeof(length)) == SUCCESS) {
		char nameBuffer[256];
		if (p_storage->Read(nameBuffer, length) == SUCCESS) {
			nameBuffer[length] = '\0';
			if (strcmp(nameBuffer, g_endOfVariables) == 0) {
				// 2 -> "This was the last entry, done reading."
				result = 2;
			}
			else {
				if (p_storage->Read(&length, sizeof(length)) == SUCCESS) {
					char valueBuffer[256];
					if (p_storage->Read(valueBuffer, length) == SUCCESS) {
						valueBuffer[length] = '\0';
						p_to->SetVariable(nameBuffer, valueBuffer);
						result = SUCCESS;
					}
				}
			}
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1003a170
void LegoGameState::GetFileSavePath(MxString* p_outPath, MxU8 p_slotn)
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

// FUNCTION: LEGO1 0x1003a2e0
void LegoGameState::SerializePlayersInfo(MxS16 p_flags)
{
	LegoFile fileStorage;
	MxString playersGSI = MxString(m_savePath);

	playersGSI += "\\";
	playersGSI += g_playersGSI;

	if (fileStorage.Open(playersGSI.GetData(), p_flags) == SUCCESS) {
		if (fileStorage.IsReadMode()) {
			Read(&fileStorage, &m_playerCount);
		}
		else if (fileStorage.IsWriteMode()) {
			Write(&fileStorage, m_playerCount);
		}

		for (MxS16 i = 0; i < m_playerCount; i++) {
			m_players[i].ReadWrite(&fileStorage);
		}
	}
}

// FUNCTION: LEGO1 0x1003a3f0
MxResult LegoGameState::AddPlayer(Username& p_player)
{
	MxString from, to;

	if (m_playerCount == 9) {
		GetFileSavePath(&from, 8);
		DeleteFile(from.GetData());
		m_playerCount--;
	}

	for (MxS16 i = m_playerCount; i > 0; i--) {
		m_players[i] = m_players[i - 1];
		GetFileSavePath(&from, i - 1);
		GetFileSavePath(&to, i);
		MoveFile(from.GetData(), to.GetData());
	}

	m_playerCount++;
	m_players[0].Set(p_player);
	m_unk0x24 = m_history.m_unk0x372;
	m_history.m_unk0x372 = m_unk0x24 + 1;
	m_history.WriteScoreHistory();
	SetCurrentAct(e_act1);

	return DeleteState();
}

// FUNCTION: LEGO1 0x1003a540
void LegoGameState::SwitchPlayer(MxS16 p_playerId)
{
	if (p_playerId > 0) {
		MxString from, temp, to;

		GetFileSavePath(&from, p_playerId);
		GetFileSavePath(&temp, 36);

		Username selectedName(m_players[p_playerId]);

		MoveFile(from.GetData(), temp.GetData());

		for (MxS16 i = p_playerId; i > 0; i--) {
			m_players[i] = m_players[i - 1];
			GetFileSavePath(&from, i - 1);
			GetFileSavePath(&to, i);
			MoveFile(from.GetData(), to.GetData());
		}

		m_players[0] = selectedName;
		GetFileSavePath(&from, 0);
		MoveFile(temp.GetData(), from.GetData());
	}

	if (Load(0) != SUCCESS) {
		Init();
	}
}

// FUNCTION: LEGO1 0x1003a6e0
MxS16 LegoGameState::FindPlayer(Username& p_player)
{
	for (MxS16 i = 0; i < m_playerCount; i++) {
		if (memcmp(&m_players[i], &p_player, sizeof(p_player)) == 0) {
			return i;
		}
	}

	return -1;
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

// FUNCTION: LEGO1 0x1003bd00
void LegoGameState::Init()
{
	m_backgroundColor->SetValue("set 56 54 68");
	m_backgroundColor->SetLights();
	m_tempBackgroundColor->SetValue("set 56 54 68");
	VariableTable()->SetVariable("lightposition", "2");
	SetLightPosition(2);
	PlantManager()->Init();
	BuildingManager()->Init();
	UnkSaveDataWriter()->InitSaveData();
	AnimationManager()->FUN_1005ee80(TRUE);
	SetColors();
	RemoveActor();
	DeleteState();
	m_isDirty = FALSE;
	FindLoadedAct();
	SetCurrentAct(e_act1);

	if (m_loadedAct == e_act1) {
		Isle* isle = (Isle*) FindWorld(*g_isleScript, 0);

		Helicopter* copter = (Helicopter*) isle->Find(*g_copterScript, 1);
		if (copter) {
			isle->FUN_1001fc80(copter);
			isle->VTable0x6c(copter);
			delete copter;
		}

		DuneBuggy* dunebuggy = (DuneBuggy*) isle->Find(*g_dunecarScript, 2);
		if (dunebuggy) {
			isle->FUN_1001fc80(dunebuggy);
			isle->VTable0x6c(dunebuggy);
			delete dunebuggy;
		}

		Jetski* jetski = (Jetski*) isle->Find(*g_jetskiScript, 3);
		if (jetski) {
			isle->FUN_1001fc80(jetski);
			isle->VTable0x6c(jetski);
			delete jetski;
		}

		RaceCar* racecar = (RaceCar*) isle->Find(*g_racecarScript, 4);
		if (racecar) {
			isle->FUN_1001fc80(racecar);
			isle->VTable0x6c(racecar);
			delete racecar;
		}
	}

	m_unk0x42c = e_noArea;
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
LegoGameState::Username& LegoGameState::Username::operator=(const Username& p_other)
{
	memcpy(m_letters, p_other.m_letters, sizeof(m_letters));
	return *this;
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
