#include "modeldb.h"

DECOMP_SIZE_ASSERT(ModelDbWorld, 0x18)
DECOMP_SIZE_ASSERT(ModelDbPart, 0x18)
DECOMP_SIZE_ASSERT(ModelDbModel, 0x38)

// STUB: LEGO1 0x100276b0
MxResult ModelDbModel::Read(FILE* p_file)
{
	return SUCCESS;
}

// STUB: LEGO1 0x10027850
MxResult ModelDbPart::Read(FILE* p_file)
{
	return SUCCESS;
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

	for (MxS32 i = 0; i < numWorlds; i++) {
		MxU32 worldNameLen;
		if (fread(&worldNameLen, sizeof(worldNameLen), 1, p_file) != 1) {
			return FAILURE;
		}

		worlds[i].m_worldName = new char[worldNameLen];
		if (fread(&worlds[i].m_worldName, worldNameLen, 1, p_file) != 1) {
			return FAILURE;
		}

		MxS32 numParts;
		if (fread(&numParts, sizeof(numParts), 1, p_file) != 1) {
			return FAILURE;
		}

		worlds[i].m_partList = new ModelDbPartList();

		MxS32 j;
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
