#include "legogamestate.h"

#include "infocenterstate.h"
#include "legoanimationmanager.h"
#include "legoomni.h"
#include "legostate.h"
#include "legoutil.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "mxbackgroundaudiomanager.h"
#include "mxobjectfactory.h"
#include "mxstring.h"
#include "mxvariabletable.h"
#include "roi/legoroi.h"

#include <stdio.h>

// Based on the highest dword offset (0x42c) referenced in the constructor.
// There may be other members that come after.
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
	{"c_dbbkfny0", "lego red"},    {"c_dbbkxly0", "lego white"},  {"c_chbasey0", "lego black"},
	{"c_chbacky0", "lego black"},  {"c_chdishy0", "lego white"},  {"c_chhorny0", "lego black"},
	{"c_chljety1", "lego black"},  {"c_chrjety1", "lego black"},  {"c_chmidly0", "lego black"},
	{"c_chmotry0", "lego blue"},   {"c_chsidly0", "lego black"},  {"c_chsidry0", "lego black"},
	{"c_chstuty0", "lego black"},  {"c_chtaily0", "lego black"},  {"c_chwindy1", "lego black"},
	{"c_dbfbrdy0", "lego red"},    {"c_dbflagy0", "lego yellow"}, {"c_dbfrfny4", "lego red"},
	{"c_dbfrxly0", "lego white"},  {"c_dbhndly0", "lego white"},  {"c_dbltbry0", "lego white"},
	{"c_jsdashy0", "lego white"},  {"c_jsexhy0", "lego black"},   {"c_jsfrnty5", "lego black"},
	{"c_jshndly0", "lego red"},    {"c_jslsidy0", "lego black"},  {"c_jsrsidy0", "lego black"},
	{"c_jsskiby0", "lego red"},    {"c_jswnshy5", "lego white"},  {"c_rcbacky6", "lego green"},
	{"c_rcedgey0", "lego green"},  {"c_rcfrmey0", "lego red"},    {"c_rcfrnty6", "lego green"},
	{"c_rcmotry0", "lego white"},  {"c_rcsidey0", "lego green"},  {"c_rcstery0", "lego white"},
	{"c_rcstrpy0", "lego yellow"}, {"c_rctailya", "lego white"},  {"c_rcwhl1y0", "lego white"},
	{"c_rcwhl2y0", "lego white"},  {"c_jsbasey0", "lego white"},  {"c_chblady0", "lego black"},
	{"c_chseaty0", "lego white"},
};

// NOTE: This offset = the end of the variables table, the last entry
// in that table is a special entry, the string "END_OF_VARIABLES"
extern const char* g_endOfVariables;

// FUNCTION: LEGO1 0x10039550
LegoGameState::LegoGameState()
{
	// TODO
	SetROIHandlerFunction();

	this->m_stateCount = 0;
	this->m_unk0x0c = 0;
	this->m_savePath = NULL;
	this->m_currentArea = 0;
	this->m_previousArea = 0;
	this->m_unk0x42c = 0;
	this->m_isDirty = FALSE;
	this->m_loadedAct = e_actNotFound;

	m_backgroundColor = new LegoBackgroundColor("backgroundcolor", "set 56 54 68");
	VariableTable()->SetVariable(m_backgroundColor);

	m_tempBackgroundColor = new LegoBackgroundColor("tempBackgroundcolor", "set 56 54 68");
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

// STUB: LEGO1 0x10039780
void LegoGameState::FUN_10039780(MxU8)
{
	// TODO
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

	if (!infocenterState || infocenterState->GetInfocenterBufferElement(0) == NULL) {
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
			fileStream.Write(&m_unk0x0c, 1);

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
MxResult LegoGameState::WriteVariable(LegoStorage* p_stream, MxVariableTable* p_from, const char* p_variableName)
{
	MxResult result = FAILURE;
	const char* variableValue = p_from->GetVariable(p_variableName);

	if (variableValue) {
		MxU8 length = strlen(p_variableName);
		if (p_stream->Write((char*) &length, 1) == SUCCESS) {
			if (p_stream->Write(p_variableName, length) == SUCCESS) {
				length = strlen(variableValue);
				if (p_stream->Write((char*) &length, 1) == SUCCESS) {
					result = p_stream->Write((char*) variableValue, length);
				}
			}
		}
	}
	return result;
}

// FUNCTION: LEGO1 0x1003a020
MxResult LegoGameState::WriteEndOfVariables(LegoStorage* p_stream)
{
	MxU8 len = strlen(g_endOfVariables);
	if (p_stream->Write(&len, 1) == SUCCESS) {
		return p_stream->Write(g_endOfVariables, len);
	}
	return FAILURE;
}

// 95% match, just some instruction ordering differences on the call to
// MxVariableTable::SetVariable at the end.
// FUNCTION: LEGO1 0x1003a080
MxS32 LegoGameState::ReadVariable(LegoStorage* p_stream, MxVariableTable* p_to)
{
	MxS32 result = 1;
	MxU8 length;

	if (p_stream->Read((char*) &length, 1) == SUCCESS) {
		char nameBuffer[256];
		if (p_stream->Read(nameBuffer, length) == SUCCESS) {
			nameBuffer[length] = '\0';
			if (strcmp(nameBuffer, g_endOfVariables) == 0) {
				// 2 -> "This was the last entry, done reading."
				result = 2;
			}
			else {
				if (p_stream->Read((char*) &length, 1) == SUCCESS) {
					char valueBuffer[256];
					if (p_stream->Read(valueBuffer, length) == SUCCESS) {
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
void LegoGameState::StopArea(MxU32 p_area)
{
	if (p_area == 0) {
		p_area = m_previousArea;
	}

	switch (p_area) {
	case 1:
		InvokeAction(Extra::e_stop, *g_isleScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_isleScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_sndAnimScript, 0, NULL);
		break;
	case 2:
		InvokeAction(Extra::e_stop, *g_infomainScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_infomainScript, 0, NULL);
		break;
	case 3:
		InvokeAction(Extra::e_stop, *g_infodoorScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_infodoorScript, 0, NULL);
		break;
	case 5:
		InvokeAction(Extra::e_stop, *g_elevbottScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_elevbottScript, 0, NULL);
		break;
	case 6:
	case 7:
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
	case 8:
		RemoveFromWorld(*g_isleScript, 0x45b, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x45c, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x45d, *g_isleScript, 0);
		break;
	case 9:
		RemoveFromWorld(*g_isleScript, 0x475, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x476, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x477, *g_isleScript, 0);
		break;
	case 10:
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
	case 0xb:
		RemoveFromWorld(*g_isleScript, 0x47a, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x47b, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x47c, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x47d, *g_isleScript, 0);
		break;
	case 0xc:
		InvokeAction(Extra::e_stop, *g_regbookScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_regbookScript, 0, NULL);
		break;
	case 0xd:
		InvokeAction(Extra::e_stop, *g_infoscorScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_infoscorScript, 0, NULL);
		break;
	case 0xe:
		InvokeAction(Extra::e_stop, *g_jetraceScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_jetraceScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_jetracerScript, 0, NULL);
		break;
	case 0x12:
		InvokeAction(Extra::e_stop, *g_carraceScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_carraceScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_carracerScript, 0, NULL);
		break;
	case 0x1a:
		Lego()->RemoveWorld(*g_garageScript, 0);
		InvokeAction(Extra::e_stop, *g_garageScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_garageScript, 0, NULL);
		break;
	case 0x1b:
		RemoveFromWorld(*g_isleScript, 0x489, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x48a, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x48b, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x48c, *g_isleScript, 0);
		break;
	case 0x1e:
		InvokeAction(Extra::e_stop, *g_hospitalScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_hospitalScript, 0, NULL);
		break;
	case 0x22:
		InvokeAction(Extra::e_stop, *g_policeScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_policeScript, 0, NULL);
		break;
	case 0x23:
		RemoveFromWorld(*g_isleScript, 0x47f, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x480, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x481, *g_isleScript, 0);
		RemoveFromWorld(*g_isleScript, 0x482, *g_isleScript, 0);
		break;
	case 0x24:
		InvokeAction(Extra::e_stop, *g_jukeboxScript, 0x2f, NULL);
		InvokeAction(Extra::e_stop, *g_copterScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_copterScript, 0, NULL);
		break;
	case 0x25:
		InvokeAction(Extra::e_stop, *g_jukeboxScript, 0x31, NULL);
		InvokeAction(Extra::e_stop, *g_dunecarScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_dunecarScript, 0, NULL);
		break;
	case 0x26:
		InvokeAction(Extra::e_stop, *g_jukeboxScript, 0x33, NULL);
		InvokeAction(Extra::e_stop, *g_jetskiScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_jetskiScript, 0, NULL);
		break;
	case 0x27:
		InvokeAction(Extra::e_stop, *g_jukeboxScript, 0x35, NULL);
		InvokeAction(Extra::e_stop, *g_racecarScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_racecarScript, 0, NULL);
		break;
	case 0x2e:
		if (m_currentArea != 2) {
			InvokeAction(Extra::e_stop, *g_act2mainScript, 0, NULL);
			InvokeAction(Extra::e_close, *g_act2mainScript, 0, NULL);
		}
		break;
	case 0x2f:
		if (m_currentArea != 2) {
			InvokeAction(Extra::e_stop, *g_act3Script, 0, NULL);
			InvokeAction(Extra::e_close, *g_act3Script, 0, NULL);
		}
		break;
	case 0x35:
		InvokeAction(Extra::e_stop, *g_jukeboxwScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_jukeboxwScript, 0, NULL);
		break;
	case 0x38:
		InvokeAction(Extra::e_disable, *g_histbookScript, 0, NULL);
		InvokeAction(Extra::e_stop, *g_histbookScript, 0, NULL);
		InvokeAction(Extra::e_close, *g_histbookScript, 0, NULL);
		break;
	}
}

// FUNCTION: LEGO1 0x1003b060
void LegoGameState::SwitchArea(MxU32 p_area)
{
	m_previousArea = m_currentArea;
	m_currentArea = p_area;

	FUN_10015820(TRUE, LegoOmni::c_disableInput | LegoOmni::c_disable3d);
	BackgroundAudioManager()->Stop();
	AnimationManager()->FUN_1005ef10();
	VideoManager()->SetUnk0x554(FALSE);

	LegoWorld* world;

	switch (p_area) {
	case 1:
		InvokeAction(Extra::ActionType::e_opendisk, *g_isleScript, 0, NULL);
		break;
	case 2:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_infomainScript, 0, NULL);
		break;
	case 3:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_infodoorScript, 0, NULL);
		break;
	case 4:
	case 0xf:
	case 0x10:
	case 0x11:
	case 0x13:
	case 0x14:
	case 0x15:
	case 0x16:
	case 0x19:
	case 0x1d:
	case 0x1f:
	case 0x20:
	case 0x39:
	case 0x3a:
	case 0x3b:
	case 0x3c:
	case 0x3d:
	case 0x40:
	case 0x42:
		world = FindWorld(*g_isleScript, 0);
		if (world != NULL) {
			if (world->GetUnknown0xd0().empty()) {
				break;
			}
			else {
#ifdef COMPAT_MODE
				{
					MxNotificationParam param(c_notificationType20, NULL);
					NotificationManager()->Send(world, &param);
				}
#else
				NotificationManager()->Send(world, &MxNotificationParam(c_notificationType20, NULL));
#endif
				break;
			}
		}
		InvokeAction(Extra::ActionType::e_opendisk, *g_isleScript, 0, NULL);
		break;
	case 5:
		InvokeAction(Extra::ActionType::e_opendisk, *g_elevbottScript, 0, NULL);
		break;
	case 6:
	case 7:
		world = FindWorld(*g_isleScript, 0);

		if (world == NULL) {
			InvokeAction(Extra::ActionType::e_opendisk, *g_isleScript, 0, NULL);
		}
		else if (!world->GetUnknown0xd0().empty()) {
#ifdef COMPAT_MODE
			{
				MxNotificationParam param(c_notificationType20, NULL);
				NotificationManager()->Send(world, &param);
			}
#else
			NotificationManager()->Send(world, &MxNotificationParam(c_notificationType20, NULL));
#endif
		}
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, 1050, NULL);
		break;
	case 8:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, 1114, NULL);
		break;
	case 9:
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, 1140, NULL);
		break;
	case 10:
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, 1118, NULL);
		break;
	case 11:
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, 1145, NULL);
		break;
	case 12:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_regbookScript, 0, NULL);
		break;
	case 13:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_infoscorScript, 0, NULL);
		break;
	case 14:
		if (m_previousArea == 2) {
			m_currentArea = 15;

			world = FindWorld(*g_isleScript, 0);
			if (world != NULL) {
				if (world->GetUnknown0xd0().empty()) {
					return;
				}
				else {
#ifdef COMPAT_MODE
					{
						MxNotificationParam param(c_notificationType20, NULL);
						NotificationManager()->Send(world, &param);
					}
#else
					NotificationManager()->Send(world, &MxNotificationParam(c_notificationType20, NULL));
#endif
				}
				return;
			}
			else {
				InvokeAction(Extra::ActionType::e_opendisk, *g_isleScript, 0, NULL);
				break;
			}
		}

		InvokeAction(Extra::ActionType::e_opendisk, *g_jetraceScript, 0, NULL);
		break;
	case 18:
		if (m_previousArea == 2) {
			m_currentArea = 19;

			world = FindWorld(*g_isleScript, 0);
			if (world != NULL) {
				if (world->GetUnknown0xd0().empty()) {
					return;
				}
				else {
#ifdef COMPAT_MODE
					{
						MxNotificationParam param(c_notificationType20, NULL);
						NotificationManager()->Send(world, &param);
					}
#else
					NotificationManager()->Send(world, &MxNotificationParam(c_notificationType20, NULL));
#endif
				}
				return;
			}
		}

		InvokeAction(Extra::ActionType::e_opendisk, *g_carraceScript, 0, NULL);
		break;
	case 26:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_garageScript, 0, NULL);
		break;

	// TODO: implement other cases
	case 56:
		VideoManager()->SetUnk0x554(TRUE);
		InvokeAction(Extra::ActionType::e_opendisk, *g_histbookScript, 0, NULL);
		break;
	default:
		break;
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

// STUB: LEGO1 0x1003c870
void LegoGameState::ScoreStruct::WriteScoreHistory()
{
	// TODO
}

// STUB: LEGO1 0x1003ccf0
void LegoGameState::ScoreStruct::FUN_1003ccf0(LegoFile&)
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
		m_unk0xa6.WriteScoreHistory();
	}

	if (stream.Open(savePath.GetData(), p_flags) == SUCCESS) {
		m_unk0xa6.FUN_1003ccf0(stream);
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
