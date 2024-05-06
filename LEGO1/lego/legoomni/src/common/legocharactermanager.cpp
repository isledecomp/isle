#include "legocharactermanager.h"

#include "3dmanager/lego3dmanager.h"
#include "legoanimactor.h"
#include "legocharacters.h"
#include "legoextraactor.h"
#include "legogamestate.h"
#include "legovariables.h"
#include "legovideomanager.h"
#include "misc.h"
#include "misc/legocontainer.h"
#include "misc/legostorage.h"
#include "mxmisc.h"
#include "mxvariabletable.h"
#include "realtime/realtime.h"
#include "roi/legolod.h"
#include "viewmanager/viewmanager.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(LegoCharacter, 0x08)
DECOMP_SIZE_ASSERT(LegoCharacterManager, 0x08)

// GLOBAL: LEGO1 0x100fc4e4
char* LegoCharacterManager::g_customizeAnimFile = NULL;

// GLOBAL: LEGO1 0x100fc4d8
MxU32 g_unk0x100fc4d8 = 50;

// GLOBAL: LEGO1 0x100fc4dc
MxU32 g_unk0x100fc4dc = 66;

// GLOBAL: LEGO1 0x100fc4e8
MxU32 g_unk0x100fc4e8 = 0;

// GLOBAL: LEGO1 0x100fc4ec
MxU32 g_unk0x100fc4ec = 2;

// GLOBAL: LEGO1 0x100fc4f0
MxU32 g_unk0x100fc4f0 = 0;

// GLOBAL: LEGO1 0x10104f20
LegoCharacterInfo g_characterInfo[66];

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
	for (MxS32 i = 0; i < _countof(g_characterInfo); i++) {
		g_characterInfo[i] = g_characterInfoInit[i];
	}
}

// FUNCTION: LEGO1 0x100832a0
void LegoCharacterManager::FUN_100832a0()
{
	for (MxS32 i = 0; i < _countof(g_characterInfo); i++) {
		LegoCharacterInfo* info = GetInfo(g_characterInfo[i].m_name);

		if (info != NULL) {
			LegoExtraActor* actor = info->m_actor;

			if (actor != NULL && actor->IsA("LegoExtraActor")) {
				LegoROI* roi = g_characterInfo[i].m_roi;
				MxU32 refCount = GetRefCount(roi);

				while (refCount != 0) {
					FUN_10083db0(roi);
					refCount = GetRefCount(roi);
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x10083310
MxResult LegoCharacterManager::Write(LegoStorage* p_storage)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < _countof(g_characterInfo); i++) {
		LegoCharacterInfo* info = &g_characterInfo[i];

		if (p_storage->Write(&info->m_unk0x0c, sizeof(info->m_unk0x0c)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_unk0x10, sizeof(info->m_unk0x10)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_unk0x14, sizeof(info->m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_parts[c_infohatPart].m_unk0x08, sizeof(info->m_parts[c_infohatPart].m_unk0x08)) !=
			SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_parts[c_infohatPart].m_unk0x14, sizeof(info->m_parts[c_infohatPart].m_unk0x14)) !=
			SUCCESS) {
			goto done;
		}
		if (p_storage->Write(
				&info->m_parts[c_infogronPart].m_unk0x14,
				sizeof(info->m_parts[c_infogronPart].m_unk0x14)
			) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_parts[c_armlftPart].m_unk0x14, sizeof(info->m_parts[c_armlftPart].m_unk0x14)) !=
			SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_parts[c_armrtPart].m_unk0x14, sizeof(info->m_parts[c_armrtPart].m_unk0x14)) !=
			SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_parts[c_leglftPart].m_unk0x14, sizeof(info->m_parts[c_leglftPart].m_unk0x14)) !=
			SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_parts[c_legrtPart].m_unk0x14, sizeof(info->m_parts[c_legrtPart].m_unk0x14)) !=
			SUCCESS) {
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

	for (MxS32 i = 0; i < _countof(g_characterInfo); i++) {
		LegoCharacterInfo* info = &g_characterInfo[i];

		if (p_storage->Read(&info->m_unk0x0c, sizeof(info->m_unk0x0c)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_unk0x10, sizeof(info->m_unk0x10)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_unk0x14, sizeof(info->m_unk0x14)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_parts[c_infohatPart].m_unk0x08, sizeof(info->m_parts[c_infohatPart].m_unk0x08)) !=
			SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_parts[c_infohatPart].m_unk0x14, sizeof(info->m_parts[c_infohatPart].m_unk0x14)) !=
			SUCCESS) {
			goto done;
		}
		if (p_storage->Read(
				&info->m_parts[c_infogronPart].m_unk0x14,
				sizeof(info->m_parts[c_infogronPart].m_unk0x14)
			) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_parts[c_armlftPart].m_unk0x14, sizeof(info->m_parts[c_armlftPart].m_unk0x14)) !=
			SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_parts[c_armrtPart].m_unk0x14, sizeof(info->m_parts[c_armrtPart].m_unk0x14)) !=
			SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_parts[c_leglftPart].m_unk0x14, sizeof(info->m_parts[c_leglftPart].m_unk0x14)) !=
			SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_parts[c_legrtPart].m_unk0x14, sizeof(info->m_parts[c_legrtPart].m_unk0x14)) !=
			SUCCESS) {
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
	LegoCharacterMap::iterator it = m_characters->find(const_cast<char*>(p_key));

	if (it != m_characters->end()) {
		character = (*it).second;
		character->AddRef();
	}

	if (character == NULL) {
		LegoROI* roi = CreateROI(p_key);

		if (roi == NULL) {
			goto done;
		}

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

done:
	if (character != NULL) {
		if (p_createEntity && character->m_roi->GetEntity() == NULL) {
			LegoExtraActor* actor = new LegoExtraActor();

			actor->SetROI(character->m_roi, FALSE, FALSE);
			actor->SetType(LegoEntity::e_character);
			actor->SetFlag(LegoActor::c_bit2);
			GetInfo(p_key)->m_actor = actor;
		}

		return character->m_roi;
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10083bc0
MxU32 LegoCharacterManager::GetRefCount(LegoROI* p_roi)
{
	LegoCharacterMap::iterator it;

	for (it = m_characters->begin(); it != m_characters->end(); it++) {
		LegoCharacter* character = (*it).second;
		LegoROI* roi = character->m_roi;

		if (roi == p_roi) {
			return character->m_refCount;
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x10083c30
// FUNCTION: BETA10 0x10074701
void LegoCharacterManager::FUN_10083c30(const char* p_name)
{
	LegoCharacter* character = NULL;
	LegoCharacterMap::iterator it = m_characters->find(const_cast<char*>(p_name));

	if (it != m_characters->end()) {
		character = (*it).second;

		if (character->RemoveRef() == 0) {
			LegoCharacterInfo* info = GetInfo(p_name);
			LegoEntity* entity = character->m_roi->GetEntity();

			if (entity != NULL) {
				entity->SetROI(NULL, FALSE, FALSE);
			}

			RemoveROI(character->m_roi);

			delete[] (*it).first;
			delete (*it).second;

			m_characters->erase(it);

			if (info != NULL) {
				if (info->m_actor != NULL) {
					info->m_actor->ClearFlag(LegoEntity::c_bit2);
					delete info->m_actor;
				}
				else if (entity != NULL && entity->GetFlagsIsSet(LegoEntity::c_bit2)) {
					entity->ClearFlag(LegoEntity::c_bit2);
					delete entity;
				}

				info->m_roi = NULL;
				info->m_actor = NULL;
			}
		}
	}
}

// FUNCTION: LEGO1 0x10083db0
void LegoCharacterManager::FUN_10083db0(LegoROI* p_roi)
{
	LegoCharacter* character = NULL;
	LegoCharacterMap::iterator it;

	for (it = m_characters->begin(); it != m_characters->end(); it++) {
		character = (*it).second;

		if (character->m_roi == p_roi) {
			if (character->RemoveRef() == 0) {
				LegoCharacterInfo* info = GetInfo(character->m_roi->GetName());
				LegoEntity* entity = character->m_roi->GetEntity();

				if (entity != NULL) {
					entity->SetROI(NULL, FALSE, FALSE);
				}

				RemoveROI(character->m_roi);

				delete[] (*it).first;
				delete (*it).second;

				m_characters->erase(it);

				if (info != NULL) {
					if (info->m_actor != NULL) {
						info->m_actor->ClearFlag(LegoEntity::c_bit2);
						delete info->m_actor;
					}
					else if (entity != NULL && entity->GetFlagsIsSet(LegoEntity::c_bit2)) {
						entity->ClearFlag(LegoEntity::c_bit2);
						delete entity;
					}

					info->m_roi = NULL;
					info->m_actor = NULL;
				}
			}

			return;
		}
	}
}

// FUNCTION: LEGO1 0x10083f10
void LegoCharacterManager::FUN_10083f10(LegoROI* p_roi)
{
	LegoCharacter* character = NULL;
	LegoCharacterMap::iterator it;

	for (it = m_characters->begin(); it != m_characters->end(); it++) {
		character = (*it).second;

		if (character->m_roi == p_roi) {
			if (character->RemoveRef() == 0) {
				LegoEntity* entity = character->m_roi->GetEntity();

				if (entity != NULL) {
					entity->SetROI(NULL, FALSE, FALSE);
				}

				RemoveROI(character->m_roi);

				delete[] (*it).first;
				delete (*it).second;

				m_characters->erase(it);

				if (entity != NULL && entity->GetFlagsIsSet(LegoEntity::c_bit2)) {
					entity->ClearFlag(LegoEntity::c_bit2);
					delete entity;
				}
			}

			return;
		}
	}
}

// FUNCTION: LEGO1 0x10084010
void LegoCharacterManager::RemoveROI(LegoROI* p_roi)
{
	VideoManager()->Get3DManager()->Remove(*p_roi);
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
	MxS32 i;

	Tgl::Renderer* renderer = VideoManager()->GetRenderer();
	ViewLODListManager* lodManager = GetViewLODListManager();
	LegoTextureContainer* textureContainer = TextureContainer();
	LegoCharacterInfo* info = GetInfo(p_key);

	if (info == NULL) {
		goto done;
	}

	if (!strcmpi(p_key, "pep")) {
		LegoCharacterInfo* pepper = GetInfo("pepper");

		info->m_unk0x0c = pepper->m_unk0x0c;
		info->m_unk0x10 = pepper->m_unk0x10;
		info->m_unk0x14 = pepper->m_unk0x14;

		for (i = 0; i < _countof(info->m_parts); i++) {
			info->m_parts[i] = pepper->m_parts[i];
		}
	}

	roi = new LegoROI(renderer);
	roi->SetName(p_key);

	boundingSphere.Center()[0] = g_characterLODs[c_topLOD].m_boundingSphere[0];
	boundingSphere.Center()[1] = g_characterLODs[c_topLOD].m_boundingSphere[1];
	boundingSphere.Center()[2] = g_characterLODs[c_topLOD].m_boundingSphere[2];
	boundingSphere.Radius() = g_characterLODs[c_topLOD].m_boundingSphere[3];
	roi->SetBoundingSphere(boundingSphere);

	boundingBox.Min()[0] = g_characterLODs[c_topLOD].m_boundingBox[0];
	boundingBox.Min()[1] = g_characterLODs[c_topLOD].m_boundingBox[1];
	boundingBox.Min()[2] = g_characterLODs[c_topLOD].m_boundingBox[2];
	boundingBox.Max()[0] = g_characterLODs[c_topLOD].m_boundingBox[3];
	boundingBox.Max()[1] = g_characterLODs[c_topLOD].m_boundingBox[4];
	boundingBox.Max()[2] = g_characterLODs[c_topLOD].m_boundingBox[5];
	roi->SetUnknown0x80(boundingBox);

	comp = new CompoundObject();
	roi->SetComp(comp);

	for (i = 0; i < _countof(g_characterLODs) - 1; i++) {
		char lodName[256];
		LegoCharacterInfo::Part& part = info->m_parts[i];

		const char* parentName;
		if (i == 0 || i == 1) {
			parentName = part.m_unk0x04[part.m_unk0x00[part.m_unk0x08]];
		}
		else {
			parentName = g_characterLODs[i + 1].m_parentName;
		}

		ViewLODList* lodList = lodManager->Lookup(parentName);
		MxS32 lodSize = lodList->Size();
		sprintf(lodName, "%s%d", p_key, i);
		ViewLODList* dupLodList = lodManager->Create(lodName, lodSize);

		for (MxS32 j = 0; j < lodSize; j++) {
			LegoLOD* lod = (LegoLOD*) (*lodList)[j];
			LegoLOD* clone = lod->Clone(renderer);
			dupLodList->PushBack(clone);
		}

		lodList->Release();
		lodList = dupLodList;

		LegoROI* childROI = new LegoROI(renderer, lodList);
		lodList->Release();

		childROI->SetName(g_characterLODs[i + 1].m_name);
		childROI->SetParentROI(roi);

		BoundingSphere childBoundingSphere;
		childBoundingSphere.Center()[0] = g_characterLODs[i + 1].m_boundingSphere[0];
		childBoundingSphere.Center()[1] = g_characterLODs[i + 1].m_boundingSphere[1];
		childBoundingSphere.Center()[2] = g_characterLODs[i + 1].m_boundingSphere[2];
		childBoundingSphere.Radius() = g_characterLODs[i + 1].m_boundingSphere[3];
		childROI->SetBoundingSphere(childBoundingSphere);

		BoundingBox childBoundingBox;
		childBoundingBox.Min()[0] = g_characterLODs[i + 1].m_boundingBox[0];
		childBoundingBox.Min()[1] = g_characterLODs[i + 1].m_boundingBox[1];
		childBoundingBox.Min()[2] = g_characterLODs[i + 1].m_boundingBox[2];
		childBoundingBox.Max()[0] = g_characterLODs[i + 1].m_boundingBox[3];
		childBoundingBox.Max()[1] = g_characterLODs[i + 1].m_boundingBox[4];
		childBoundingBox.Max()[2] = g_characterLODs[i + 1].m_boundingBox[5];
		childROI->SetUnknown0x80(childBoundingBox);

		CalcLocalTransform(
			Mx3DPointFloat(g_characterLODs[i + 1].m_position),
			Mx3DPointFloat(g_characterLODs[i + 1].m_direction),
			Mx3DPointFloat(g_characterLODs[i + 1].m_up),
			mat
		);
		childROI->WrappedSetLocalTransform(mat);

		if (g_characterLODs[i + 1].m_flags & LegoCharacterLOD::c_flag1 &&
			(i != 0 || part.m_unk0x00[part.m_unk0x08] != 0)) {

			LegoTextureInfo* textureInfo = textureContainer->Get(part.m_unk0x10[part.m_unk0x0c[part.m_unk0x14]]);

			if (textureInfo != NULL) {
				childROI->FUN_100a9210(textureInfo);
				childROI->FUN_100a9170(1.0F, 1.0F, 1.0F, 0.0F);
			}
		}
		else if (g_characterLODs[i + 1].m_flags & LegoCharacterLOD::c_flag2 || (i == 0 && part.m_unk0x00[part.m_unk0x08] == 0)) {
			LegoFloat red, green, blue, alpha;
			childROI->FUN_100a9bf0(part.m_unk0x10[part.m_unk0x0c[part.m_unk0x14]], red, green, blue, alpha);
			childROI->FUN_100a9170(red, green, blue, alpha);
		}

		comp->push_back(childROI);
	}

	CalcLocalTransform(
		Mx3DPointFloat(g_characterLODs[c_topLOD].m_position),
		Mx3DPointFloat(g_characterLODs[c_topLOD].m_direction),
		Mx3DPointFloat(g_characterLODs[c_topLOD].m_up),
		mat
	);
	roi->WrappedSetLocalTransform(mat);

	info->m_roi = roi;
	success = TRUE;

done:
	if (!success && roi != NULL) {
		delete roi;
		roi = NULL;
	}

	return roi;
}

// FUNCTION: LEGO1 0x100849a0
// FUNCTION: BETA10 0x10075b51
MxBool LegoCharacterManager::FUN_100849a0(LegoROI* p_roi, LegoTextureInfo* p_textureInfo)
{
	LegoResult result = SUCCESS;
	LegoROI* head = FindChildROI(p_roi, g_characterLODs[c_headLOD].m_name);

	if (head != NULL) {
		char lodName[256];

		ViewLODList* lodList = GetViewLODListManager()->Lookup(g_characterLODs[c_headLOD].m_parentName);
		MxS32 lodSize = lodList->Size();
		sprintf(lodName, "%s%s%d", p_roi->GetName(), "head", g_unk0x100fc4e8++);
		ViewLODList* dupLodList = GetViewLODListManager()->Create(lodName, lodSize);

		Tgl::Renderer* renderer = VideoManager()->GetRenderer();

		if (p_textureInfo == NULL) {
			LegoCharacterInfo* info = GetInfo(p_roi->GetName());
			LegoCharacterInfo::Part& part = info->m_parts[c_headPart];
			p_textureInfo = TextureContainer()->Get(part.m_unk0x10[part.m_unk0x0c[part.m_unk0x14]]);
		}

		for (MxS32 i = 0; i < lodSize; i++) {
			LegoLOD* lod = (LegoLOD*) (*lodList)[i];
			LegoLOD* clone = lod->Clone(renderer);

			if (p_textureInfo != NULL) {
				clone->FUN_100aad70(p_textureInfo);
			}

			dupLodList->PushBack(clone);
		}

		lodList->Release();
		lodList = dupLodList;

		if (head->GetUnknown0xe0() >= 0) {
			VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager()->FUN_100a66a0(head);
		}

		head->SetLODList(lodList);
		lodList->Release();
	}

	return head != NULL;
}

// FUNCTION: LEGO1 0x10084c00
MxBool LegoCharacterManager::Exists(const char* p_key)
{
	for (MxU32 i = 0; i < _countof(g_characterInfo); i++) {
		if (!strcmpi(g_characterInfo[i].m_name, p_key)) {
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10084c40
LegoExtraActor* LegoCharacterManager::GetActor(const char* p_key)
{
	LegoCharacterInfo* info = GetInfo(p_key);

	if (info != NULL) {
		return info->m_actor;
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10084c60
LegoCharacterInfo* LegoCharacterManager::GetInfo(const char* p_key)
{
	MxU32 i;

	for (i = 0; i < _countof(g_characterInfo); i++) {
		if (!strcmpi(g_characterInfo[i].m_name, p_key)) {
			break;
		}
	}

	if (i < _countof(g_characterInfo)) {
		return &g_characterInfo[i];
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10084cb0
LegoCharacterInfo* LegoCharacterManager::GetInfo(LegoROI* p_roi)
{
	MxU32 i;

	for (i = 0; i < _countof(g_characterInfo); i++) {
		if (g_characterInfo[i].m_roi == p_roi) {
			break;
		}
	}

	if (i < _countof(g_characterInfo)) {
		return &g_characterInfo[i];
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10084cf0
// FUNCTION: BETA10 0x10075fe2
LegoROI* LegoCharacterManager::FindChildROI(LegoROI* p_roi, const char* p_name)
{
	const CompoundObject* comp = p_roi->GetComp();

#ifdef COMPAT_MODE
	for (CompoundObject::const_iterator it = comp->begin(); !(it == comp->end()); it++) {
#else
	for (CompoundObject::iterator it = comp->begin(); !(it == comp->end()); it++) {
#endif
		LegoROI* roi = (LegoROI*) *it;

		if (!strcmpi(p_name, roi->GetName())) {
			return roi;
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10084ec0
MxBool LegoCharacterManager::SwitchHat(LegoROI* p_roi)
{
	LegoCharacterInfo* info = GetInfo(p_roi->GetName());

	if (info == NULL) {
		return FALSE;
	}

	LegoCharacterInfo::Part& part = info->m_parts[c_infohatPart];

	part.m_unk0x08++;
	MxU8 unk0x00 = part.m_unk0x00[part.m_unk0x08];

	if (unk0x00 == 0xff) {
		part.m_unk0x08 = 0;
		unk0x00 = part.m_unk0x00[part.m_unk0x08];
	}

	LegoROI* childROI = FindChildROI(p_roi, g_characterLODs[c_infohatLOD].m_name);

	if (childROI != NULL) {
		char lodName[256];

		ViewLODList* lodList = GetViewLODListManager()->Lookup(part.m_unk0x04[unk0x00]);
		MxS32 lodSize = lodList->Size();
		sprintf(lodName, "%s%d", p_roi->GetName(), g_unk0x100fc4ec++);
		ViewLODList* dupLodList = GetViewLODListManager()->Create(lodName, lodSize);

		Tgl::Renderer* renderer = VideoManager()->GetRenderer();
		LegoFloat red, green, blue, alpha;
		LegoROI::FUN_100a9bf0(part.m_unk0x10[part.m_unk0x0c[part.m_unk0x14]], red, green, blue, alpha);

		for (MxS32 i = 0; i < lodSize; i++) {
			LegoLOD* lod = (LegoLOD*) (*lodList)[i];
			LegoLOD* clone = lod->Clone(renderer);
			clone->FUN_100aacb0(red, green, blue, alpha);
			dupLodList->PushBack(clone);
		}

		lodList->Release();
		lodList = dupLodList;

		if (childROI->GetUnknown0xe0() >= 0) {
			VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager()->FUN_100a66a0(childROI);
		}

		childROI->SetLODList(lodList);
		lodList->Release();
	}

	return TRUE;
}

// FUNCTION: LEGO1 0x10085140
MxU32 LegoCharacterManager::FUN_10085140(LegoROI* p_roi, MxBool p_und)
{
	LegoCharacterInfo* info = GetInfo(p_roi);

	if (p_und) {
		return info->m_unk0x14 + g_unk0x100fc4dc;
	}

	if (info != NULL) {
		return info->m_unk0x0c + g_unk0x100fc4d8;
	}

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

// FUNCTION: LEGO1 0x10085210
LegoROI* LegoCharacterManager::FUN_10085210(const char* p_name, const char* p_lodName, MxBool p_createEntity)
{
	LegoROI* roi = NULL;

	MxMatrix mat;
	Tgl::Renderer* renderer = VideoManager()->GetRenderer();
	ViewLODListManager* lodManager = GetViewLODListManager();
	LegoTextureContainer* textureContainer = TextureContainer();
	ViewLODList* lodList = lodManager->Lookup(p_lodName);

	if (lodList == NULL || lodList->Size() == 0) {
		return NULL;
	}

	roi = new LegoROI(renderer, lodList);

	const char* name;
	char buf[20];

	if (p_name != NULL) {
		name = p_name;
	}
	else {
		sprintf(buf, "autoROI_%d", g_unk0x100fc4f0++);
		name = buf;
	}

	roi->SetName(name);
	lodList->Release();

	if (roi != NULL && FUN_10085870(roi) != SUCCESS) {
		delete roi;
		roi = NULL;
	}

	if (roi != NULL) {
		roi->SetVisibility(FALSE);

		LegoCharacter* character = new LegoCharacter(roi);
		char* key = new char[strlen(name) + 1];

		if (key != NULL) {
			strcpy(key, name);
			(*m_characters)[key] = character;
			VideoManager()->Get3DManager()->Add(*roi);

			if (p_createEntity && roi->GetEntity() == NULL) {
				LegoEntity* entity = new LegoEntity();

				entity->SetROI(roi, FALSE, FALSE);
				entity->SetType(LegoEntity::e_unk4);
				entity->SetFlag(LegoActor::c_bit2);
			}
		}
	}

	return roi;
}

// FUNCTION: LEGO1 0x10085870
MxResult LegoCharacterManager::FUN_10085870(LegoROI* p_roi)
{
	MxResult result = FAILURE;

	BoundingSphere boundingSphere;
	BoundingBox boundingBox;

	const Tgl::MeshBuilder* meshBuilder = ((ViewLOD*) p_roi->GetLOD(0))->GetMeshBuilder();

	if (meshBuilder != NULL) {
		float min[3], max[3];

		FILLVEC3(min, 88888.0);
		FILLVEC3(max, -88888.0);
		meshBuilder->GetBoundingBox(min, max);

		float center[3];
		center[0] = (min[0] + max[0]) / 2.0f;
		center[1] = (min[1] + max[1]) / 2.0f;
		center[2] = (min[2] + max[2]) / 2.0f;
		SET3(boundingSphere.Center(), center);

		float radius[3];
		VMV3(radius, max, min);
		boundingSphere.Radius() = sqrt(NORMSQRD3(radius)) / 2.0;

		p_roi->SetBoundingSphere(boundingSphere);

		SET3(boundingBox.Min(), min);
		SET3(boundingBox.Max(), max);

		p_roi->SetUnknown0x80(boundingBox);

		p_roi->VTable0x14();

		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x10085a80
LegoROI* LegoCharacterManager::FUN_10085a80(const char* p_name, const char* p_lodName, MxBool p_createEntity)
{
	return FUN_10085210(p_name, p_lodName, p_createEntity);
}
