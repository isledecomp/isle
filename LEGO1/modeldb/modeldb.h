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

	MxString m_name;      // 0x00
	undefined4 m_unk0x10; // 0x10
	undefined4 m_unk0x14; // 0x14
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
		MxS32 compare = !strcmpi(p_a->m_name.GetData(), p_b->m_name.GetData());

		if (compare == 0) {
			p_b->m_unk0x10 = p_a->m_unk0x10;
			p_b->m_unk0x14 = p_a->m_unk0x14;
		}

		return compare;
	} // vtable+0x14

	// SYNTHETIC: LEGO1 0x10027d70
	// ModelDbPartList::`scalar deleting destructor'

private:
	undefined m_unk0x18;
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

// SIZE 0x38
struct ModelDbModel {
	MxResult Read(FILE* p_file);

	undefined m_unk0x00[0x38]; // 0x00
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

#endif // MODELDB_H
