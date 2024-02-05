#include "legounksavedatawriter.h"

#include "legogamestate.h"
#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(LegoSaveDataEntry3, 0x108);

// GLOBAL: LEGO1 0x10104f20
LegoSaveDataEntry3 g_saveData3[66];

// STUB: LEGO1 0x100832a0
void LegoUnkSaveDataWriter::FUN_100832a0()
{
	// TODO
}

// FUNCTION: LEGO1 0x10083310
MxResult LegoUnkSaveDataWriter::WriteSaveData3(LegoStorage* p_stream)
{
	MxResult result = FAILURE;

	// This should probably be a for loop but I can't figure out how to
	// make it match as a for loop.
	LegoSaveDataEntry3* entry = g_saveData3;
	const LegoSaveDataEntry3* end = &g_saveData3[66];

	while (TRUE) {
		if (p_stream->Write(&entry->m_savePart1, 4) != SUCCESS) {
			break;
		}
		if (p_stream->Write(&entry->m_savePart2, 4) != SUCCESS) {
			break;
		}
		if (p_stream->Write(&entry->m_savePart3, 1) != SUCCESS) {
			break;
		}
		if (p_stream->Write(&entry->m_currentFrame, 1) != SUCCESS) {
			break;
		}
		if (p_stream->Write(&entry->m_savePart5, 1) != SUCCESS) {
			break;
		}
		if (p_stream->Write(&entry->m_savePart6, 1) != SUCCESS) {
			break;
		}
		if (p_stream->Write(&entry->m_savePart7, 1) != SUCCESS) {
			break;
		}
		if (p_stream->Write(&entry->m_savePart8, 1) != SUCCESS) {
			break;
		}
		if (p_stream->Write(&entry->m_savePart9, 1) != SUCCESS) {
			break;
		}
		if (p_stream->Write(&entry->m_savePart10, 1) != SUCCESS) {
			break;
		}
		if (++entry >= end) {
			result = SUCCESS;
			break;
		}
	}
	return result;
}

// STUB: LEGO1 0x10083500
AutoROI* LegoUnkSaveDataWriter::FUN_10083500(undefined4, undefined4)
{
	// TODO
	// involves an STL map with a _Nil node at 0x100fc508
	return NULL;
}

// STUB: LEGO1 0x10083db0
void LegoUnkSaveDataWriter::FUN_10083db0(LegoROI* p_roi)
{
	// TODO
}
