#include "legogamestate.h"

#include "infocenterstate.h"
#include "legoanimationmanager.h"
#include "legoomni.h"
#include "legostate.h"
#include "legostream.h"
#include "legoutil.h"
#include "legovideomanager.h"
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
	this->m_unk0xc = 0;
	this->m_savePath = NULL;
	this->m_unk0x424 = 0;
	this->m_prevArea = 0;
	this->m_unk0x42c = 0;
	this->m_isDirty = FALSE;
	this->m_currentAct = -1;

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
			if (state)
				delete state;
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

// FUNCTION: LEGO1 0x10039980
MxResult LegoGameState::Save(MxULong p_slot)
{
	MxResult result;
	InfocenterState* infocenterState = (InfocenterState*) GameState()->GetState("InfocenterState");

	if (!infocenterState || infocenterState->GetInfocenterBufferElement(0) == NULL)
		result = SUCCESS;
	else {
		result = FAILURE;
		MxVariableTable* variableTable = VariableTable();
		MxString savePath;
		GetFileSavePath(&savePath, p_slot);
		LegoFileStream fileStream;
		if (fileStream.Open(savePath.GetData(), LegoStream::c_writeBit) != FAILURE) {
			MxU32 maybeVersion = 0x1000C;
			fileStream.Write(&maybeVersion, 4);
			fileStream.Write(&m_unk0x24, 2);
			fileStream.Write(&m_unk0x10, 2);
			fileStream.Write(&m_unk0xc, 1);

			for (MxS32 i = 0; i < sizeof(g_colorSaveData) / sizeof(g_colorSaveData[0]); ++i) {
				if (LegoStream::WriteVariable(&fileStream, variableTable, g_colorSaveData[i].m_targetName) == FAILURE)
					return result;
			}

			if (LegoStream::WriteVariable(&fileStream, variableTable, "backgroundcolor") != FAILURE) {
				if (LegoStream::WriteVariable(&fileStream, variableTable, "lightposition") != FAILURE) {
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
	if (m_savePath != NULL)
		delete[] m_savePath;

	if (p_savePath) {
		m_savePath = new char[strlen(p_savePath) + 1];
		strcpy(m_savePath, p_savePath);
	}
	else
		m_savePath = NULL;
}

// FUNCTION: LEGO1 0x1003a020
MxResult LegoGameState::WriteEndOfVariables(LegoStream* p_stream)
{
	MxU8 len = strlen(g_endOfVariables);
	if (p_stream->Write(&len, 1) == SUCCESS)
		return p_stream->Write(g_endOfVariables, len);
	return FAILURE;
}

// FUNCTION: LEGO1 0x1003a170
void LegoGameState::GetFileSavePath(MxString* p_outPath, MxULong p_slotn)
{
	char baseForSlot[2] = "0";
	char path[1024] = "";

	// Save path base
	if (m_savePath != NULL)
		strcpy(path, m_savePath);

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

// STUB: LEGO1 0x1003a720
void LegoGameState::FUN_1003a720(MxU32)
{
	// TODO
}

// STUB: LEGO1 0x1003b060
void LegoGameState::HandleAction(MxU32 p_area)
{
	m_prevArea = p_area;
	BackgroundAudioManager()->Stop();
	AnimationManager()->FUN_1005ef10();
	VideoManager()->SetUnk0x554(0);

	MxAtomId* script = g_isleScript;
	switch (p_area) {
	case 1:
		break;
	case 2:
		VideoManager()->SetUnk0x554(1);
		script = g_infomainScript;
		break;
	case 3:
		VideoManager()->SetUnk0x554(1);
		script = g_infodoorScript;
		break;

		// TODO: implement other cases
	}

	InvokeAction(Extra::ActionType::e_opendisk, *script, 0, NULL);
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
	for (MxS32 i = 0; i < m_stateCount; ++i)
		if (m_stateArray[i]->IsA(p_stateName))
			return m_stateArray[i];
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
	for (targetIndex = 0; targetIndex < m_stateCount; ++targetIndex)
		if (m_stateArray[targetIndex]->IsA(p_state->ClassName()))
			break;

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

	if (m_stateArray[targetIndex])
		delete m_stateArray[targetIndex];
	m_stateArray[targetIndex] = p_state;
}

// STUB: LEGO1 0x1003c870
void LegoGameState::ScoreStruct::WriteScoreHistory()
{
	// TODO
}

// STUB: LEGO1 0x1003ccf0
void LegoGameState::ScoreStruct::FUN_1003ccf0(LegoFileStream&)
{
	// TODO
}

// FUNCTION: LEGO1 0x1003cdd0
void LegoGameState::SerializeScoreHistory(MxS16 p_flags)
{
	LegoFileStream stream;
	MxString savePath(m_savePath);
	savePath += "\\";
	savePath += g_historyGSI;

	if (p_flags == LegoStream::c_writeBit) {
		m_unk0xa6.WriteScoreHistory();
	}

	if (stream.Open(savePath.GetData(), (LegoStream::OpenFlags) p_flags) == SUCCESS) {
		m_unk0xa6.FUN_1003ccf0(stream);
	}
}

// FUNCTION: LEGO1 0x1003cea0
void LegoGameState::SetSomeEnumState(undefined4 p_state)
{
	m_unk0x10 = p_state;
}

// FUNCTION: LEGO1 0x1003ceb0
void LegoGameState::FUN_1003ceb0()
{
	if (FindEntityByAtomIdOrEntityId(*g_isleScript, 0)) {
		m_currentAct = 0;
	}
	else if (FindEntityByAtomIdOrEntityId(*g_act2mainScript, 0)) {
		m_currentAct = 1;
	}
	else if (FindEntityByAtomIdOrEntityId(*g_act3Script, 0)) {
		m_currentAct = 2;
	}
	else {
		m_currentAct = -1;
	}
}
