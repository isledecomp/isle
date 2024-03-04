#ifndef MODELDB_H
#define MODELDB_H

#include "decomp.h"
#include "mxlist.h"
#include "mxstring.h"
#include "mxtypes.h"

#include <stdio.h>

// SIZE 0x18
struct ModelDbPart {
	MxResult Read(FILE* p_file);

	MxString m_roiName;          // 0x00
	undefined4 m_partDataLength; // 0x10
	undefined4 m_partDataOffset; // 0x14
};

// VTABLE: LEGO1 0x100d6888
// class MxCollection<ModelDbPart *>

// VTABLE: LEGO1 0x100d68a0
// class MxList<ModelDbPart *>

// VTABLE: LEGO1 0x100d68b8
// SIZE 0x1c
class ModelDbPartList : public MxList<ModelDbPart*> {
public:
	ModelDbPartList() { m_unk0x18 = 1; }

	// FUNCTION: LEGO1 0x10027c40
	MxS8 Compare(ModelDbPart* p_a, ModelDbPart* p_b) override
	{
		MxS32 compare = strcmpi(p_a->m_roiName.GetData(), p_b->m_roiName.GetData());

		if (compare == 0) {
			p_b->m_partDataLength = p_a->m_partDataLength;
			p_b->m_partDataOffset = p_a->m_partDataOffset;
		}

		return compare;
	} // vtable+0x14

	// SYNTHETIC: LEGO1 0x10027d70
	// ModelDbPartList::`scalar deleting destructor'

private:
	undefined m_unk0x18;
};

// VTABLE: LEGO1 0x100d68d0
// class MxListCursor<ModelDbPart *>

// VTABLE: LEGO1 0x100d68e8
// SIZE 0x10
class ModelDbPartListCursor : public MxListCursor<ModelDbPart*> {
public:
	ModelDbPartListCursor(ModelDbPartList* p_list) : MxListCursor<ModelDbPart*>(p_list) {}
};

// TEMPLATE: LEGO1 0x10027c70
// MxCollection<ModelDbPart *>::Compare

// TEMPLATE: LEGO1 0x10027c80
// MxCollection<ModelDbPart *>::~MxCollection<ModelDbPart *>

// TEMPLATE: LEGO1 0x10027cd0
// MxCollection<ModelDbPart *>::Destroy

// TEMPLATE: LEGO1 0x10027ce0
// MxList<ModelDbPart *>::~MxList<ModelDbPart *>

// SYNTHETIC: LEGO1 0x10027de0
// MxCollection<ModelDbPart *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10027e50
// MxList<ModelDbPart *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10027f00
// ModelDbPartListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x10027f70
// MxListCursor<ModelDbPart *>::~MxListCursor<ModelDbPart *>

// SYNTHETIC: LEGO1 0x10027fc0
// MxListCursor<ModelDbPart *>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x10028030
// ModelDbPartListCursor::~ModelDbPartListCursor

// SIZE 0x38
struct ModelDbModel {
	MxResult Read(FILE* p_file);

	char* m_modelName;     // 0x00
	undefined4 m_unk0x04;  // 0x04
	undefined4 m_unk0x08;  // 0x08
	char* m_presenterName; // 0x0c
	float m_location[3];   // 0x10
	float m_direction[3];  // 0x1c
	float m_up[3];         // 0x28
	undefined m_unk0x34;   // 0x34
};

// SIZE 0x18
struct ModelDbWorld {
	char* m_worldName;           // 0x00
	ModelDbPartList* m_partList; // 0x04
	ModelDbModel* m_models;      // 0x08
	MxS32 m_numModels;           // 0x0c
	undefined m_unk0x10[0x08];   // 0x10
};

MxResult ReadModelDbWorlds(FILE* p_file, ModelDbWorld*& p_worlds, MxS32& p_numWorlds);
void FreeModelDbWorlds(ModelDbWorld*& p_worlds, MxS32 p_numWorlds);

#endif // MODELDB_H
