#include "modeldb.h"

DECOMP_SIZE_ASSERT(ModelDbWorld, 0x18)
DECOMP_SIZE_ASSERT(ModelDbPart, 0x18)
DECOMP_SIZE_ASSERT(ModelDbModel, 0x38)
DECOMP_SIZE_ASSERT(ModelDbPartList, 0x1c)
DECOMP_SIZE_ASSERT(ModelDbPartListCursor, 0x10)

// FUNCTION: LEGO1 0x100276b0
MxResult ModelDbModel::Read(FILE* p_file)
{
	MxU32 len;

	if (fread(&len, sizeof(len), 1, p_file) != 1) {
		return FAILURE;
	}

	m_modelName = new char[len];
	if (fread(m_modelName, len, 1, p_file) != 1) {
		return FAILURE;
	}

	if (fread(&m_unk0x04, sizeof(m_unk0x04), 1, p_file) != 1) {
		return FAILURE;
	}
	if (fread(&m_unk0x08, sizeof(m_unk0x08), 1, p_file) != 1) {
		return FAILURE;
	}
	if (fread(&len, sizeof(len), 1, p_file) != 1) {
		return FAILURE;
	}

	m_presenterName = new char[len];
	if (fread(m_presenterName, len, 1, p_file) != 1) {
		return FAILURE;
	}

	if (fread(&m_location, sizeof(*m_location), 3, p_file) != 3) {
		return FAILURE;
	}
	if (fread(&m_direction, sizeof(*m_direction), 3, p_file) != 3) {
		return FAILURE;
	}
	if (fread(&m_up, sizeof(*m_up), 3, p_file) != 3) {
		return FAILURE;
	}

	return fread(&m_unk0x34, sizeof(m_unk0x34), 1, p_file) == 1 ? SUCCESS : FAILURE;
}

// FUNCTION: LEGO1 0x10027850
MxResult ModelDbPart::Read(FILE* p_file)
{
	MxU32 len;
	char buff[128];

	if (fread(&len, sizeof(len), 1, p_file) != 1) {
		return FAILURE;
	}

	// Critical bug: buffer overrun
	if (fread(buff, len, 1, p_file) != 1) {
		return FAILURE;
	}

	m_roiName = buff;

	if (fread(&m_partDataLength, sizeof(m_partDataLength), 1, p_file) != 1) {
		return FAILURE;
	}

	return fread(&m_partDataOffset, sizeof(m_partDataOffset), 1, p_file) == 1 ? SUCCESS : FAILURE;
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
