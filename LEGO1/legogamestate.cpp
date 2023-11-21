#include "legogamestate.h"

#include "infocenterstate.h"
#include "legoomni.h"
#include "legoroi.h"
#include "legostate.h"
#include "legostream.h"
#include "mxobjectfactory.h"
#include "mxstring.h"
#include "mxvariabletable.h"

// Based on the highest dword offset (0x42c) referenced in the constructor.
// There may be other members that come after.
DECOMP_SIZE_ASSERT(LegoGameState, 0x430)

// GLOBAL OFFSET: LEGO1 0x100f3e40
const char* g_fileExtensionGS = ".GS";

// GLOBAL OFFSET: LEGO1 0x100f3e58
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
// GLOBAL OFFSET: LEGO1 0x100f3e50
extern const char* s_endOfVariables;

// OFFSET: LEGO1 0x10039550
LegoGameState::LegoGameState()
{
	// TODO
	SetROIHandlerFunction();

	m_stateCount = 0;
	m_backgroundColor = new LegoBackgroundColor("backgroundcolor", "set 56 54 68");
	VariableTable()->SetVariable(m_backgroundColor);

	m_tempBackgroundColor = new LegoBackgroundColor("tempBackgroundcolor", "set 56 54 68");
	VariableTable()->SetVariable(m_tempBackgroundColor);

	m_fullScreenMovie = new LegoFullScreenMovie("fsmovie", "disable");
	VariableTable()->SetVariable(m_fullScreenMovie);

	VariableTable()->SetVariable("lightposition", "2");
	SerializeScoreHistory(1);
}

// OFFSET: LEGO1 0x10039720
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

// OFFSET: LEGO1 0x10039980
MxResult LegoGameState::Save(MxULong p_slot)
{
	MxResult result;
	InfocenterState* infocenterState = (InfocenterState*) GameState()->GetState("InfocenterState");
	if (!infocenterState || infocenterState->GetInfocenterBufferElement(0) == 0)
		result = SUCCESS;
	else {
		result = FAILURE;
		MxVariableTable* variableTable = VariableTable();
		MxString savePath;
		GetFileSavePath(&savePath, p_slot);
		LegoFileStream fileStream;
		if (fileStream.Open(savePath.GetData(), LegoStream::WriteBit) != FAILURE) {
			MxU32 maybeVersion = 0x1000C;
			fileStream.Write(&maybeVersion, 4);
			fileStream.Write(&m_unk24, 2);
			fileStream.Write(&m_unk10, 2);
			fileStream.Write(&m_unkC, 1);

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

// OFFSET: LEGO1 0x10039c60 STUB
MxResult LegoGameState::Load(MxULong)
{
	// TODO
	return 0;
}

// OFFSET: LEGO1 0x10039f00
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

// OFFSET: LEGO1 0x1003a020
MxResult LegoGameState::WriteEndOfVariables(LegoStream* p_stream)
{
	MxU8 len = strlen(s_endOfVariables);
	if (p_stream->Write(&len, 1) == SUCCESS)
		return p_stream->Write(s_endOfVariables, len);
	return FAILURE;
}

// OFFSET: LEGO1 0x1003a170
void LegoGameState::GetFileSavePath(MxString* p_outPath, MxULong p_slotn)
{
	char baseForSlot[2] = "0";
	char path[1024] = "";

	// Save path base
	if (m_savePath != NULL)
		strcpy(path, m_savePath);

	// Slot: "G0", "G1", ...
	strcat(path, "G");
	baseForSlot[0] += p_slotn;
	strcat(path, baseForSlot);

	// Extension: ".GS"
	strcat(path, g_fileExtensionGS);
	*p_outPath = MxString(path);
}

// OFFSET: LEGO1 0x1003a2e0 STUB
void LegoGameState::SerializePlayersInfo(MxS16 p)
{
	// TODO
}

// OFFSET: LEGO1 0x1003a720 STUB
void LegoGameState::FUN_1003a720(MxU32 p_unk)
{
	// TODO
}

// OFFSET: LEGO1 0x1003b060 STUB
void LegoGameState::HandleAction(MxU32 p_unk)
{
	// TODO
}

// OFFSET: LEGO1 0x1003bac0
void LegoGameState::SetROIHandlerFunction()
{
	LegoROI::SetSomeHandlerFunction(&ROIHandlerFunction);
}

// OFFSET: LEGO1 0x1003bad0
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

// OFFSET: LEGO1 0x1003bbb0
LegoState* LegoGameState::GetState(COMPAT_CONST char* p_stateName)
{
	for (MxS32 i = 0; i < m_stateCount; ++i)
		if (m_stateArray[i]->IsA(p_stateName))
			return m_stateArray[i];
	return NULL;
}

// OFFSET: LEGO1 0x1003bc00
LegoState* LegoGameState::CreateState(COMPAT_CONST char* p_stateName)
{
	LegoState* newState = (LegoState*) ObjectFactory()->Create(p_stateName);
	RegisterState(newState);

	return newState;
}

// OFFSET: LEGO1 0x1003bc30
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

// OFFSET: LEGO1 0x1003cdd0 STUB
void LegoGameState::SerializeScoreHistory(MxS16 p)
{
	// TODO
}

// OFFSET: LEGO1 0x1003cea0
void LegoGameState::SetSomeEnumState(undefined4 p_state)
{
	m_unk10 = p_state;
}
