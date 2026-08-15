#include "modeldb.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(ModelDbWorld, 0x18)
DECOMP_SIZE_ASSERT(ModelDbPart, 0x18)
DECOMP_SIZE_ASSERT(ModelDbModel, 0x38)
DECOMP_SIZE_ASSERT(ModelDbPartList, 0x1c)
DECOMP_SIZE_ASSERT(ModelDbPartListCursor, 0x10)

// FUNCTION: LEGO1 0x10027690
// FUNCTION: BETA10 0x100e5620
void ModelDbModel::Free()
{
	delete[] m_modelName;
	delete[] m_presenterName;
}

// The model database had a writer half beside its reader: BETA10 carries
// ModelDbModel::Dump (0x100e566b, 8 fprintf) and ModelDbModel::Write
// (0x100e579b, 10 fwrite) between Free and Read, and the ModelDbPart pair
// below it. Retail dropped every caller, so /OPT:REF discarded the bodies --
// but not before the reference had made LINK pull fprintf.obj and fwrite.obj
// out of LIBCMT, which is why retail seats them at module 110 (first scan,
// immediately before fread.obj, in exactly this Dump->Write->Read order)
// while a build without them can only reach fwrite through legostorage.cpp,
// a library member, 131 module positions late.

// FUNCTION: BETA10 0x100e566b
void ModelDbModel::Dump(FILE* p_file)
{
	fprintf(p_file, "%s\n", m_modelName);
	fprintf(p_file, "%d\n", m_modelDataLength);
	fprintf(p_file, "%d\n", m_modelDataOffset);
	fprintf(p_file, "%s\n", m_presenterName);
	fprintf(p_file, "%4.4f, %4.4f, %4.4f\n", m_location[0], m_location[1], m_location[2]);
	fprintf(p_file, "%4.4f, %4.4f, %4.4f\n", m_direction[0], m_direction[1], m_direction[2]);
	fprintf(p_file, "%4.4f, %4.4f, %4.4f\n", m_up[0], m_up[1], m_up[2]);
	fprintf(p_file, "%d\n", m_visible);
}

// FUNCTION: BETA10 0x100e579b
MxResult ModelDbModel::Write(FILE* p_file)
{
	MxU32 len;

	len = strlen(m_modelName) + 1;
	if (fwrite(&len, sizeof(MxU32), 1, p_file) != 1) {
		return FAILURE;
	}
	if (fwrite(m_modelName, len, 1, p_file) != 1) {
		return FAILURE;
	}

	if (fwrite(&m_modelDataLength, sizeof(MxU32), 1, p_file) != 1) {
		return FAILURE;
	}
	if (fwrite(&m_modelDataOffset, sizeof(MxU32), 1, p_file) != 1) {
		return FAILURE;
	}

	len = strlen(m_presenterName) + 1;
	if (fwrite(&len, sizeof(MxU32), 1, p_file) != 1) {
		return FAILURE;
	}
	if (fwrite(m_presenterName, len, 1, p_file) != 1) {
		return FAILURE;
	}

	if (fwrite(&m_location, sizeof(float), 3, p_file) != 3) {
		return FAILURE;
	}
	if (fwrite(&m_direction, sizeof(float), 3, p_file) != 3) {
		return FAILURE;
	}
	if (fwrite(&m_up, sizeof(float), 3, p_file) != 3) {
		return FAILURE;
	}
	if (fwrite(&m_visible, sizeof(MxU8), 1, p_file) != 1) {
		return FAILURE;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100276b0
MxResult ModelDbModel::Read(FILE* p_file)
{
	MxU32 len;

	if (fread(&len, sizeof(MxU32), 1, p_file) != 1) {
		return FAILURE;
	}

	m_modelName = new char[len];
	if (fread(m_modelName, len, 1, p_file) != 1) {
		return FAILURE;
	}

	if (fread(&m_modelDataLength, sizeof(MxU32), 1, p_file) != 1) {
		return FAILURE;
	}
	if (fread(&m_modelDataOffset, sizeof(MxU32), 1, p_file) != 1) {
		return FAILURE;
	}
	if (fread(&len, sizeof(MxU32), 1, p_file) != 1) {
		return FAILURE;
	}

	m_presenterName = new char[len];
	if (fread(m_presenterName, len, 1, p_file) != 1) {
		return FAILURE;
	}

	if (fread(&m_location, sizeof(float), 3, p_file) != 3) {
		return FAILURE;
	}
	if (fread(&m_direction, sizeof(float), 3, p_file) != 3) {
		return FAILURE;
	}
	if (fread(&m_up, sizeof(float), 3, p_file) != 3) {
		return FAILURE;
	}
	if (fread(&m_visible, sizeof(MxU8), 1, p_file) != 1) {
		return FAILURE;
	}

	return SUCCESS;
}

// FUNCTION: BETA10 0x100e5bfe
void ModelDbPart::Dump(FILE* p_file)
{
	fprintf(p_file, "%s\n", m_roiName.GetData());
	fprintf(p_file, "%d\n", m_partDataLength);
	fprintf(p_file, "%d\n", m_partDataOffset);
}

// FUNCTION: BETA10 0x100e5c60
MxResult ModelDbPart::Write(FILE* p_file)
{
	MxU32 len;

	len = strlen(m_roiName.GetData()) + 1;
	if (fwrite(&len, sizeof(MxU32), 1, p_file) != 1) {
		return FAILURE;
	}
	if (fwrite(m_roiName.GetData(), len, 1, p_file) != 1) {
		return FAILURE;
	}

	if (fwrite(&m_partDataLength, sizeof(undefined4), 1, p_file) != 1) {
		return FAILURE;
	}
	if (fwrite(&m_partDataOffset, sizeof(undefined4), 1, p_file) != 1) {
		return FAILURE;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10027850
MxResult ModelDbPart::Read(FILE* p_file)
{
	MxU32 len;
	char buff[128];

	if (fread(&len, sizeof(MxU32), 1, p_file) != 1) {
		return FAILURE;
	}

	// (modernization) critical bug: buffer overrun
	if (fread(buff, len, 1, p_file) != 1) {
		return FAILURE;
	}

	m_roiName = buff;

	if (fread(&m_partDataLength, sizeof(undefined4), 1, p_file) != 1) {
		return FAILURE;
	}
	if (fread(&m_partDataOffset, sizeof(undefined4), 1, p_file) != 1) {
		return FAILURE;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10027910
MxResult ReadModelDbWorlds(FILE* dbf, ModelDbWorld*& newworld, MxS32& p_numWorlds)
{
	assert(dbf);
	assert(newworld);

	newworld = NULL;
	p_numWorlds = 0;

	MxS32 numWorlds;
	if (fread(&numWorlds, sizeof(numWorlds), 1, dbf) != 1) {
		return FAILURE;
	}

	ModelDbWorld* world = new ModelDbWorld[numWorlds];
	assert(world);

	MxS32 worldNameLen, numParts, ii, j;

	for (ii = 0; ii < numWorlds; ii++) {
		if (fread(&worldNameLen, sizeof(MxS32), 1, dbf) != 1) {
			return FAILURE;
		}

		world[ii].m_worldName = new char[worldNameLen];
		assert(world[ii].m_worldName);

		if (fread(world[ii].m_worldName, worldNameLen, 1, dbf) != 1) {
			return FAILURE;
		}

		if (fread(&numParts, sizeof(MxS32), 1, dbf) != 1) {
			return FAILURE;
		}

		world[ii].m_partlist = new ModelDbPartList();
		assert(world[ii].m_partlist);

		for (j = 0; j < numParts; j++) {
			ModelDbPart* part = new ModelDbPart();
			assert(part);

			if (part->Read(dbf) != SUCCESS) {
				return FAILURE;
			}

			world[ii].m_partlist->Append(part);
		}

		if (fread(&world[ii].m_numModels, sizeof(MxS32), 1, dbf) != 1) {
			return FAILURE;
		}

		world[ii].m_modarr = new ModelDbModel[world[ii].m_numModels];
		assert(world[ii].m_modarr);

		for (j = 0; j < world[ii].m_numModels; j++) {
			if (world[ii].m_modarr[j].Read(dbf) != SUCCESS) {
				return FAILURE;
			}
		}
	}

	newworld = world;
	p_numWorlds = numWorlds;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10028080
// FUNCTION: BETA10 0x100e6431
void FreeModelDbWorlds(ModelDbWorld*& p_worlds, MxS32 p_numWorlds)
{
	ModelDbWorld* worlds = p_worlds;

	for (MxS32 i = 0; i < p_numWorlds; i++) {
		delete[] worlds[i].m_worldName;

		ModelDbPartListCursor cursor(worlds[i].m_partlist);
		ModelDbPart* part;

		while (cursor.Next(part)) {
			delete part;
		}

		delete worlds[i].m_partlist;

		ModelDbModel* models = worlds[i].m_modarr;
		for (MxS32 j = 0; j < worlds[i].m_numModels; j++) {
			models[j].Free();
		}

		delete[] worlds[i].m_modarr;
	}

	delete[] p_worlds;
	p_worlds = NULL;
}
