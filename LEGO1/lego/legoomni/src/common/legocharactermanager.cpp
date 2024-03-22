#include "legocharactermanager.h"

#include "legoanimactor.h"
#include "legocharacters.h"
#include "legogamestate.h"
#include "legovideomanager.h"
#include "misc.h"
#include "misc/legocontainer.h"
#include "mxmisc.h"
#include "realtime/realtime.h"
#include "roi/legolod.h"
#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(LegoCharacter, 0x08)
DECOMP_SIZE_ASSERT(LegoCharacterManager, 0x08)

// GLOBAL: LEGO1 0x100fc4e4
char* LegoCharacterManager::g_customizeAnimFile = NULL;

// GLOBAL: LEGO1 0x10104f20
LegoCharacterData g_characterData[66];

// FUNCTION: LEGO1 0x10082a20
LegoCharacterManager::LegoCharacterManager()
{
	m_characters = new LegoCharacterMap();
	Init();

	m_customizeAnimFile = new CustomizeAnimFileVariable("CUSTOMIZE_ANIM_FILE");
	VariableTable()->SetVariable(m_customizeAnimFile);
}

// FUNCTION: LEGO1 0x10083270
void LegoCharacterManager::Init()
{
	for (MxS32 i = 0; i < _countof(g_characterData); i++) {
		g_characterData[i] = g_characterDataInit[i];
	}
}

// STUB: LEGO1 0x100832a0
void LegoCharacterManager::FUN_100832a0()
{
	// TODO
}

// FUNCTION: LEGO1 0x10083310
MxResult LegoCharacterManager::Write(LegoStorage* p_storage)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < _countof(g_characterData); i++) {
		LegoCharacterData* data = &g_characterData[i];

		if (p_storage->Write(&data->m_unk0x0c, sizeof(data->m_unk0x0c)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_unk0x10, sizeof(data->m_unk0x10)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_unk0x14, sizeof(data->m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_parts[1].m_unk0x08, sizeof(data->m_parts[1].m_unk0x08)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_parts[1].m_unk0x14, sizeof(data->m_parts[1].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_parts[2].m_unk0x14, sizeof(data->m_parts[2].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_parts[4].m_unk0x14, sizeof(data->m_parts[4].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_parts[5].m_unk0x14, sizeof(data->m_parts[5].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_parts[8].m_unk0x14, sizeof(data->m_parts[8].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&data->m_parts[9].m_unk0x14, sizeof(data->m_parts[9].m_unk0x14)) != SUCCESS) {
			goto done;
		}
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x100833f0
MxResult LegoCharacterManager::Read(LegoStorage* p_storage)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < _countof(g_characterData); i++) {
		LegoCharacterData* data = &g_characterData[i];

		if (p_storage->Read(&data->m_unk0x0c, sizeof(data->m_unk0x0c)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_unk0x10, sizeof(data->m_unk0x10)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_unk0x14, sizeof(data->m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_parts[1].m_unk0x08, sizeof(data->m_parts[1].m_unk0x08)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_parts[1].m_unk0x14, sizeof(data->m_parts[1].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_parts[2].m_unk0x14, sizeof(data->m_parts[2].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_parts[4].m_unk0x14, sizeof(data->m_parts[4].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_parts[5].m_unk0x14, sizeof(data->m_parts[5].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_parts[8].m_unk0x14, sizeof(data->m_parts[8].m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&data->m_parts[9].m_unk0x14, sizeof(data->m_parts[9].m_unk0x14)) != SUCCESS) {
			goto done;
		}
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x10083500
LegoROI* LegoCharacterManager::GetROI(const char* p_key, MxBool p_createEntity)
{
	LegoCharacter* character = NULL;
	LegoCharacterMap::iterator it = m_characters->find(p_key);

	if (it != m_characters->end()) {
		character = (*it).second;
		character->AddRef();
	}

	if (character == NULL) {
		LegoROI* roi = CreateROI(p_key);
		roi->SetVisibility(FALSE);

		if (roi != NULL) {
			character = new LegoCharacter(roi);
			char* key = new char[strlen(p_key) + 1];

			if (key != NULL) {
				strcpy(key, p_key);
				(*m_characters)[key] = character;
				VideoManager()->Get3DManager()->Add(*roi);
			}
		}
	}
	else {
		VideoManager()->Get3DManager()->Remove(*character->m_roi);
		VideoManager()->Get3DManager()->Add(*character->m_roi);
	}

	if (character != NULL) {
		if (p_createEntity && character->m_roi->GetEntity() == NULL) {
			// TODO: Match
			LegoAnimActor* actor = new LegoAnimActor(1);

			actor->SetROI(character->m_roi, FALSE, FALSE);
			actor->FUN_100114e0(0);
			actor->SetFlag(LegoActor::c_bit2);
			FUN_10084c60(p_key)->m_actor = actor;
		}

		return character->m_roi;
	}

	return NULL;
}

// STUB: LEGO1 0x10083db0
void LegoCharacterManager::FUN_10083db0(LegoROI* p_roi)
{
	// TODO
}

// STUB: LEGO1 0x10083f10
void LegoCharacterManager::FUN_10083f10(LegoROI* p_roi)
{
	// TODO
}

// FUNCTION: LEGO1 0x10084030
LegoROI* LegoCharacterManager::CreateROI(const char* p_key)
{
	MxBool success = FALSE;
	LegoROI* roi = NULL;
	BoundingSphere boundingSphere;
	BoundingBox boundingBox;
	MxMatrix mat;
	CompoundObject* comp;
	MxS32 i, j;

	Tgl::Renderer* renderer = VideoManager()->GetRenderer();
	ViewLODListManager* lodManager = GetViewLODListManager();
	LegoTextureContainer* textureContainer = TextureContainer();
	LegoCharacterData* characterData = FUN_10084c60(p_key);

	if (characterData == NULL) {
		goto done;
	}

	if (!strcmpi(p_key, "pep")) {
		LegoCharacterData* pepper = FUN_10084c60("pepper");

		characterData->m_unk0x0c = pepper->m_unk0x0c;
		characterData->m_unk0x10 = pepper->m_unk0x10;
		characterData->m_unk0x14 = pepper->m_unk0x14;

		for (i = 0; i < _countof(characterData->m_parts); i++) {
			characterData->m_parts[i] = pepper->m_parts[i];
		}
	}

	roi = new LegoROI(renderer);
	roi->SetName(p_key);

	boundingSphere.Center()[0] = g_characterLODs[0].m_boundingSphere[0];
	boundingSphere.Center()[1] = g_characterLODs[0].m_boundingSphere[1];
	boundingSphere.Center()[2] = g_characterLODs[0].m_boundingSphere[2];
	boundingSphere.Radius() = g_characterLODs[0].m_boundingSphere[3];
	roi->SetBoundingSphere(boundingSphere);

	boundingBox.Min()[0] = g_characterLODs[0].m_boundingBox[0];
	boundingBox.Min()[1] = g_characterLODs[0].m_boundingBox[1];
	boundingBox.Min()[2] = g_characterLODs[0].m_boundingBox[2];
	boundingBox.Max()[0] = g_characterLODs[0].m_boundingBox[3];
	boundingBox.Max()[1] = g_characterLODs[0].m_boundingBox[4];
	boundingBox.Max()[2] = g_characterLODs[0].m_boundingBox[5];
	roi->SetUnknown0x80(boundingBox);

	comp = new CompoundObject();
	roi->SetComp(comp);

	for (j = 0; j < _countof(g_characterLODs) - 1; j++) {
		ViewLODList *lodList, *dupLodList;
		LegoROI* childROI;
		MxU32 lodSize;
		const char* parentName;
		char lodName[64];

		// TODO
		if (j == 0 || j == 1) {
			parentName = characterData->m_parts[j]
							 .m_unk0x04[characterData->m_parts[j].m_unk0x00[characterData->m_parts[j].m_unk0x08]];
		}
		else {
			parentName = g_characterLODs[j + 1].m_parentName;
		}

		lodList = lodManager->Lookup(parentName);
		lodSize = lodList->Size();
		sprintf(lodName, "%s%d", p_key, j);
		dupLodList = lodManager->Create(lodName, lodSize);

		for (MxS32 k = 0; k < lodSize; k++) {
			dupLodList->PushBack(((LegoLOD*) (*lodList)[k])->Clone(renderer));
		}

		lodList->Release();
		lodList = dupLodList;

		childROI = new LegoROI(renderer, lodList);
		lodList->Release();

		childROI->SetName(g_characterLODs[j + 1].m_name);
		childROI->SetParentROI(roi);

		BoundingSphere childBoundingSphere;

		childBoundingSphere.Center()[0] = g_characterLODs[j + 1].m_boundingSphere[0];
		childBoundingSphere.Center()[1] = g_characterLODs[j + 1].m_boundingSphere[1];
		childBoundingSphere.Center()[2] = g_characterLODs[j + 1].m_boundingSphere[2];
		childBoundingSphere.Radius() = g_characterLODs[j + 1].m_boundingSphere[3];
		childROI->SetBoundingSphere(childBoundingSphere);

		BoundingBox childBoundingBox;
		childBoundingBox.Min()[0] = g_characterLODs[j + 1].m_boundingBox[0];
		childBoundingBox.Min()[1] = g_characterLODs[j + 1].m_boundingBox[1];
		childBoundingBox.Min()[2] = g_characterLODs[j + 1].m_boundingBox[2];
		childBoundingBox.Max()[0] = g_characterLODs[j + 1].m_boundingBox[3];
		childBoundingBox.Max()[1] = g_characterLODs[j + 1].m_boundingBox[4];
		childBoundingBox.Max()[2] = g_characterLODs[j + 1].m_boundingBox[5];
		childROI->SetUnknown0x80(childBoundingBox);

		CalcLocalTransform(
			g_characterLODs[j + 1].m_position,
			g_characterLODs[j + 1].m_direction,
			g_characterLODs[j + 1].m_up,
			mat
		);
		childROI->WrappedSetLocalTransform(mat);

		if (g_characterLODs[j + 1].m_flags & LegoCharacterLOD::c_flag1 &&
			(j != 0 || characterData->m_parts[j].m_unk0x00[characterData->m_parts[j].m_unk0x08] != 0)) {

			LegoTextureInfo* textureInfo =
				textureContainer->Get(characterData->m_parts[j].m_unk0x10[characterData->m_parts[j].m_unk0x14]);

			if (textureInfo != NULL) {
				childROI->FUN_100a9210(textureInfo);
				childROI->FUN_100a9170(1.0F, 1.0F, 1.0F, 0.0F);
			}
		}
		else if (g_characterLODs[j + 1].m_flags & LegoCharacterLOD::c_flag2 || (j == 0 && characterData->m_parts[j].m_unk0x00[characterData->m_parts[j].m_unk0x08] == 0)) {
			LegoFloat red, green, blue, alpha;
			childROI->FUN_100a9bf0(
				characterData->m_parts[j].m_unk0x10[characterData->m_parts[j].m_unk0x14],
				red,
				green,
				blue,
				alpha
			);
			childROI->FUN_100a9170(red, green, blue, alpha);
		}

		comp->push_back(childROI);
	}

	CalcLocalTransform(g_characterLODs[0].m_position, g_characterLODs[0].m_direction, g_characterLODs[0].m_up, mat);
	roi->WrappedSetLocalTransform(mat);

	characterData->m_roi = roi;
	success = TRUE;

done:
	if (!success && roi != NULL) {
		delete roi;
		roi = NULL;
	}

	return roi;
}

// STUB: LEGO1 0x10084c00
MxBool LegoCharacterManager::FUN_10084c00(const LegoChar*)
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x10084c60
LegoCharacterData* LegoCharacterManager::FUN_10084c60(const char* p_key)
{
	return NULL;
}

// STUB: LEGO1 0x10084ec0
MxBool LegoCharacterManager::FUN_10084ec0(LegoROI* p_roi)
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x10085140
MxU32 LegoCharacterManager::FUN_10085140(LegoROI*, MxBool)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x100851a0
void LegoCharacterManager::SetCustomizeAnimFile(const char* p_value)
{
	if (g_customizeAnimFile != NULL) {
		delete[] g_customizeAnimFile;
	}

	if (p_value != NULL) {
		g_customizeAnimFile = new char[strlen(p_value) + 1];

		if (g_customizeAnimFile != NULL) {
			strcpy(g_customizeAnimFile, p_value);
		}
	}
	else {
		g_customizeAnimFile = NULL;
	}
}

// STUB: LEGO1 0x10085210
LegoROI* LegoCharacterManager::FUN_10085210(const LegoChar*, LegoChar*, undefined)
{
	return NULL;
}

// FUNCTION: LEGO1 0x10085a80
LegoROI* LegoCharacterManager::FUN_10085a80(LegoChar* p_und1, LegoChar* p_und2, undefined p_und3)
{
	return FUN_10085210(p_und1, p_und2, p_und3);
}
