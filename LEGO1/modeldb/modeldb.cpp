#include "modeldb.h"

#include "windows.h"

DECOMP_SIZE_ASSERT(ModelDbWorld, 0x18)
DECOMP_SIZE_ASSERT(ModelDbPart, 0x18)
DECOMP_SIZE_ASSERT(ModelDbModel, 0x38)
DECOMP_SIZE_ASSERT(ModelDbPartList, 0x1c)
DECOMP_SIZE_ASSERT(ModelDbPartListCursor, 0x10)

// FUNCTION: LEGO1 0x100276b0
MxResult ModelDbModel::Read(FILE* p_file)
{
	MxU32 charSize;

	if (fread(&charSize, sizeof(MxU32), 1, p_file) != 1) {
		return FAILURE;
	}
	m_modelName = new char[charSize];

	if (fread(m_modelName, charSize, 1, p_file) != 1) {
		return FAILURE;
	}

	if (fread(&m_unk0x04, sizeof(undefined4), 1, p_file) != 1) {
		return FAILURE;
	}
	if (fread(&m_unk0x08, sizeof(undefined4), 1, p_file) != 1) {
		return FAILURE;
	}

	if (fread(&charSize, sizeof(MxU32), 1, p_file) != 1) {
		return FAILURE;
	}

	m_presenter = new char[charSize];
	if (fread(m_presenter, charSize, 1, p_file) != 1) {
		return FAILURE;
	}

	if (fread(&m_unk0x10, sizeof(undefined4), 3, p_file) != 3) {
		return FAILURE;
	}
	if (fread(&m_unk0x1c, sizeof(undefined4), 3, p_file) != 3) {
		return FAILURE;
	}
	if (fread(&m_unk0x28, sizeof(undefined4), 3, p_file) != 3) {
		return FAILURE;
	}

	return fread(&m_unk0x34, sizeof(undefined), 1, p_file) == 1 ? SUCCESS : FAILURE;
}

// FUNCTION: LEGO1 0x10027850
MxResult ModelDbPart::Read(FILE* p_file)
{
	MxU32 size;
	char roiNameBuffer[128];
	if (fread(&size, sizeof(MxU32), 1, p_file) != 1) {
		return FAILURE;
	}
	if (fread(roiNameBuffer, size, 1, p_file) != 1) {
		return FAILURE;
	}
	m_roiName = roiNameBuffer;

	if (fread(&m_unk0x10, sizeof(undefined4), 1, p_file) != 1) {
		return FAILURE;
	}

	return fread(&m_unk0x14, sizeof(undefined4), 1, p_file) == 1 ? SUCCESS : FAILURE;
}

// FUNCTION: LEGO1 0x10027910
MxResult ReadModelDbWorlds(FILE* p_file, ModelDbWorld*& p_worlds, MxS32& p_numWorlds)
{
	p_worlds = NULL;
	p_numWorlds = 0;

	MxS32 numWorlds;
	if (fread(&numWorlds, sizeof(numWorlds), 1, p_file) != 1) {
		return FAILURE;
	}

	ModelDbWorld* worlds = new ModelDbWorld[numWorlds];
	MxS32 worldNameLen, numParts, i, j;

	for (i = 0; i < numWorlds; i++) {
		if (fread(&worldNameLen, sizeof(worldNameLen), 1, p_file) != 1) {
			return FAILURE;
		}

		worlds[i].m_worldName = new char[worldNameLen];
		if (fread(worlds[i].m_worldName, worldNameLen, 1, p_file) != 1) {
			return FAILURE;
		}

		if (fread(&numParts, sizeof(numParts), 1, p_file) != 1) {
			return FAILURE;
		}

		worlds[i].m_partList = new ModelDbPartList();

		for (j = 0; j < numParts; j++) {
			ModelDbPart* part = new ModelDbPart();

			if (part->Read(p_file) != SUCCESS) {
				return FAILURE;
			}

			worlds[i].m_partList->Append(part);
		}

		if (fread(&worlds[i].m_numModels, sizeof(worlds[i].m_numModels), 1, p_file) != 1) {
			return FAILURE;
		}

		worlds[i].m_models = new ModelDbModel[worlds[i].m_numModels];

		for (j = 0; j < worlds[i].m_numModels; j++) {
			if (worlds[i].m_models[j].Read(p_file) != SUCCESS) {
				return FAILURE;
			}
		}
	}

	p_worlds = worlds;
	p_numWorlds = numWorlds;
	return SUCCESS;
}

// STUB: LEGO1 0x10028080
void FreeModelDbWorlds(ModelDbWorld*& p_worlds, MxS32 p_numWorlds)
{
	// TODO
}
