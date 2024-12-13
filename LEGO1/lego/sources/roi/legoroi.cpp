#include "legoroi.h"

#include "anim/legoanim.h"
#include "geom/legobox.h"
#include "geom/legosphere.h"
#include "legolod.h"
#include "misc/legocontainer.h"
#include "misc/legostorage.h"
#include "realtime/realtime.h"

#include <string.h>
#include <vec.h>

DECOMP_SIZE_ASSERT(LegoROI, 0x108)
DECOMP_SIZE_ASSERT(TimeROI, 0x10c)

// SIZE 0x14
typedef struct {
	const char* m_name;
	int m_red;
	int m_green;
	int m_blue;
	int m_alpha;
} ROIColorAlias;

// GLOBAL: LEGO1 0x101011b0
ROIColorAlias g_roiColorAliases[22] = {
	{"lego black", 0x21, 0x21, 0x21, 0},       {"lego black f", 0x21, 0x21, 0x21, 0},
	{"lego black flat", 0x21, 0x21, 0x21, 0},  {"lego blue", 0x00, 0x54, 0x8c, 0},
	{"lego blue flat", 0x00, 0x54, 0x8c, 0},   {"lego brown", 0x4a, 0x23, 0x1a, 0},
	{"lego brown flt", 0x4a, 0x23, 0x1a, 0},   {"lego brown flat", 0x4a, 0x23, 0x1a, 0},
	{"lego drk grey", 0x40, 0x40, 0x40, 0},    {"lego drk grey flt", 0x40, 0x40, 0x40, 0},
	{"lego dk grey flt", 0x40, 0x40, 0x40, 0}, {"lego green", 0x00, 0x78, 0x2d, 0},
	{"lego green flat", 0x00, 0x78, 0x2d, 0},  {"lego lt grey", 0x82, 0x82, 0x82, 0},
	{"lego lt grey flt", 0x82, 0x82, 0x82, 0}, {"lego lt grey fla", 0x82, 0x82, 0x82, 0},
	{"lego red", 0xcb, 0x12, 0x20, 0},         {"lego red flat", 0xcb, 0x12, 0x20, 0},
	{"lego white", 0xfa, 0xfa, 0xfa, 0},       {"lego white flat", 0xfa, 0xfa, 0xfa, 0},
	{"lego yellow", 0xff, 0xb9, 0x00, 0},      {"lego yellow flat", 0xff, 0xb9, 0x00, 0},
};

// GLOBAL: LEGO1 0x10101368
int g_roiConfig = 100;

// GLOBAL: LEGO1 0x10101370
const char* g_unk0x10101370[] = {"bike", "moto", NULL};

// GLOBAL: LEGO1 0x10101380
const char* g_unk0x10101380[] = {"bike", "moto", "haus", NULL};

// GLOBAL: LEGO1 0x10101390
const char* g_unk0x10101390[] = {"rcuser", "jsuser", "dunebugy", "chtrblad", "chtrbody", "chtrshld", NULL};

// GLOBAL: LEGO1 0x101013ac
ROIHandler g_unk0x101013ac = NULL;

// GLOBAL: LEGO1 0x101013b0
TextureHandler g_unk0x101013b0 = NULL;

// FUNCTION: LEGO1 0x100a81b0
void LegoROI::FUN_100a81b0(const LegoChar* p_error, const LegoChar* p_name)
{
}

// FUNCTION: LEGO1 0x100a81c0
void LegoROI::configureLegoROI(int p_roiConfig)
{
	g_roiConfig = p_roiConfig;
}

// FUNCTION: LEGO1 0x100a81d0
LegoROI::LegoROI(Tgl::Renderer* p_renderer) : ViewROI(p_renderer, NULL)
{
	m_parentROI = NULL;
	m_name = NULL;
	m_entity = NULL;
}

// FUNCTION: LEGO1 0x100a82d0
LegoROI::LegoROI(Tgl::Renderer* p_renderer, ViewLODList* p_lodList) : ViewROI(p_renderer, p_lodList)
{
	m_parentROI = NULL;
	m_name = NULL;
	m_entity = NULL;
}

// FUNCTION: LEGO1 0x100a83c0
LegoROI::~LegoROI()
{
	if (comp) {
		CompoundObject::iterator iterator;

		for (iterator = comp->begin(); !(iterator == comp->end()); ++iterator) {
			ROI* child = *iterator;

			delete child;
		}

		delete comp;
		comp = 0;
	}
	if (m_name) {
		delete[] m_name;
	}
}

// FUNCTION: LEGO1 0x100a84a0
LegoResult LegoROI::Read(
	OrientableROI* p_unk0xd4,
	Tgl::Renderer* p_renderer,
	ViewLODListManager* p_viewLODListManager,
	LegoTextureContainer* p_textureContainer,
	LegoStorage* p_storage
)
{
	LegoResult result = FAILURE;
	LegoU32 i, j;
	LegoU32 numLODs, surplusLODs;
	LegoROI* roi;
	LegoLOD* lod;
	LegoU32 length, roiLength;
	LegoChar *roiName, *textureName;
	LegoTextureInfo* textureInfo;
	ViewLODList* lodList;
	LegoU32 numROIs;
	LegoSphere sphere;
	LegoBox box;

	m_parentROI = p_unk0xd4;

	if (p_storage->Read(&length, sizeof(length)) != SUCCESS) {
		goto done;
	}
	m_name = new LegoChar[length + 1];
	if (p_storage->Read(m_name, length) != SUCCESS) {
		goto done;
	}
	m_name[length] = '\0';
	strlwr(m_name);

	if (sphere.Read(p_storage) != SUCCESS) {
		goto done;
	}

	SET3(m_sphere.Center(), sphere.GetCenter());
	m_sphere.Radius() = sphere.GetRadius();
	m_world_bounding_sphere.Radius() = m_sphere.Radius();

	if (box.Read(p_storage) != SUCCESS) {
		goto done;
	}

	SET3(m_unk0x80.Min(), box.GetMin());
	SET3(m_unk0x80.Max(), box.GetMax());

	if (p_storage->Read(&length, sizeof(length)) != SUCCESS) {
		goto done;
	}

	if (length != 0) {
		textureName = new LegoChar[length + 1];
		if (p_storage->Read(textureName, length) != SUCCESS) {
			goto done;
		}
		textureName[length] = '\0';
		strlwr(textureName);
	}
	else {
		textureName = NULL;
	}

	if (p_storage->Read(&m_unk0x100, sizeof(m_unk0x100)) != SUCCESS) {
		goto done;
	}

	if (m_unk0x100) {
		for (roiLength = strlen(m_name); roiLength; roiLength--) {
			if (m_name[roiLength - 1] < '0' || m_name[roiLength - 1] > '9') {
				break;
			}
		}

		roiName = new LegoChar[roiLength + 1];
		memcpy(roiName, m_name, roiLength);
		roiName[roiLength] = '\0';

		lodList = p_viewLODListManager->Lookup(roiName);
		delete[] roiName;

		if (lodList == NULL) {
			goto done;
		}
	}
	else {
		if (p_storage->Read(&numLODs, sizeof(numLODs)) != SUCCESS) {
			goto done;
		}

		if (!numLODs) {
			lodList = NULL;
		}
		else {
			const LegoChar* roiName = m_name;
			LegoU32 offset;

			if (p_storage->Read(&offset, sizeof(offset)) != SUCCESS) {
				goto done;
			}

			if (numLODs > g_roiConfig) {
				surplusLODs = numLODs - g_roiConfig;
				numLODs = g_roiConfig;
			}
			else {
				surplusLODs = 0;
			}

			if (g_roiConfig <= 2) {
				for (i = 0; g_unk0x10101380[i] != NULL; i++) {
					if (!strnicmp(m_name, g_unk0x10101380[i], 4)) {
						roiName = g_unk0x10101380[i];
						break;
					}
				}
			}
			else {
				for (i = 0; g_unk0x10101370[i] != NULL; i++) {
					if (!strnicmp(m_name, g_unk0x10101370[i], 4)) {
						roiName = g_unk0x10101370[i];
						break;
					}
				}
			}

			if ((lodList = p_viewLODListManager->Lookup(roiName))) {
				for (j = 0; g_unk0x10101390[j] != NULL; j++) {
					if (!strcmpi(g_unk0x10101390[j], roiName)) {
						break;
					}
				}

				if (g_unk0x10101390[j] != NULL) {
					while (lodList->Size()) {
						delete const_cast<ViewLOD*>(lodList->PopBack());
					}

					for (j = 0; j < numLODs; j++) {
						lod = new LegoLOD(p_renderer);
						if (lod->Read(p_renderer, p_textureContainer, p_storage) != SUCCESS) {
							goto done;
						}

						if (j == 0) {
							if (surplusLODs != 0 && lod->GetUnknown0x08Test8()) {
								numLODs++;
							}
						}

						lodList->PushBack(lod);
					}
				}
			}
			else {
				for (i = 0; i < numLODs; i++) {
					lod = new LegoLOD(p_renderer);
					if (lod->Read(p_renderer, p_textureContainer, p_storage) != SUCCESS) {
						goto done;
					}

					if (i == 0) {
						if (surplusLODs != 0 && lod->GetUnknown0x08Test8()) {
							numLODs++;
						}
					}

					if (i == 0 && (lodList = p_viewLODListManager->Create(roiName, numLODs)) == NULL) {
						goto done;
					}

					lodList->PushBack(lod);
				}
			}

			p_storage->SetPosition(offset);
		}
	}

	SetLODList(lodList);

	if (lodList != NULL) {
		lodList->Release();
	}

	if (textureName != NULL) {
		if (!strnicmp(textureName, "t_", 2)) {
			textureInfo = p_textureContainer->Get(textureName + 2);

			if (textureInfo == NULL) {
				goto done;
			}

			FUN_100a9210(textureInfo);
			FUN_100a9170(1.0F, 1.0F, 1.0F, 0.0F);
		}
		else {
			LegoFloat red = 1.0F;
			LegoFloat green = 0.0F;
			LegoFloat blue = 1.0F;
			LegoFloat alpha = 0.0F;
			FUN_100a9bf0(textureName, red, green, blue, alpha);
			FUN_100a9170(red, green, blue, alpha);
		}
	}

	if (p_storage->Read(&numROIs, sizeof(numROIs)) != SUCCESS) {
		goto done;
	}

	if (numROIs > 0) {
		comp = new CompoundObject;
	}

	for (i = 0; i < numROIs; i++) {
		// Create and initialize a sub-component
		roi = new LegoROI(p_renderer);
		if (roi->Read(this, p_renderer, p_viewLODListManager, p_textureContainer, p_storage) != SUCCESS) {
			goto done;
		}
		// Add the new sub-component to this ROI's protected list
		comp->push_back(roi);
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x100a8cb0
LegoResult LegoROI::FUN_100a8cb0(LegoAnimNodeData* p_data, LegoTime p_time, Matrix4& p_matrix)
{
	p_matrix.SetIdentity();
	p_data->CreateLocalTransform(p_time, p_matrix);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100a8ce0
// FUNCTION: BETA10 0x1018a815
LegoROI* LegoROI::FindChildROI(const LegoChar* p_name, LegoROI* p_roi)
{
	CompoundObject::iterator it;
	const LegoChar* name = p_roi->GetName();

	if (name != NULL && *name != '\0' && !strcmpi(name, p_name)) {
		return p_roi;
	}

	CompoundObject* comp = p_roi->comp;
	if (comp != NULL) {
		for (it = comp->begin(); it != comp->end(); it++) {
			LegoROI* roi = (LegoROI*) *it;
			name = roi->GetName();

			if (name != NULL && *name != '\0' && !strcmpi(name, p_name)) {
				return roi;
			}
		}

		for (it = comp->begin(); it != comp->end(); it++) {
			LegoROI* roi = FindChildROI(p_name, (LegoROI*) *it);

			if (roi != NULL) {
				return roi;
			}
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x100a8da0
LegoResult LegoROI::FUN_100a8da0(LegoTreeNode* p_node, const Matrix4& p_matrix, LegoTime p_time, LegoROI* p_roi)
{
	MxMatrix mat;
	LegoAnimNodeData* data = (LegoAnimNodeData*) p_node->GetData();
	const LegoChar* name = data->GetName();
	LegoROI* roi = FindChildROI(name, p_roi);

	if (roi == NULL) {
		roi = FindChildROI(name, this);
	}

	if (roi != NULL) {
		FUN_100a8cb0(data, p_time, mat);
		roi->m_local2world.Product(mat, p_matrix);
		roi->VTable0x1c();

		LegoBool und = data->FUN_100a0990(p_time);
		roi->SetVisibility(und);

		for (LegoU32 i = 0; i < p_node->GetNumChildren(); i++) {
			FUN_100a8da0(p_node->GetChild(i), roi->m_local2world, p_time, roi);
		}
	}
	else {
		FUN_100a81b0("%s ROI Not found\n", name);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100a8e80
// FUNCTION: BETA10 0x1018ab3a
void LegoROI::FUN_100a8e80(LegoTreeNode* p_node, Matrix4& p_matrix, LegoTime p_time, LegoROI** p_roiMap)
{
	MxMatrix mat;

	LegoAnimNodeData* data = (LegoAnimNodeData*) p_node->GetData();
	FUN_100a8cb0(data, p_time, mat);

	LegoROI* roi = p_roiMap[data->GetUnknown0x20()];
	if (roi != NULL) {
		roi->m_local2world.Product(mat, p_matrix);
		roi->VTable0x1c();

		LegoBool und = data->FUN_100a0990(p_time);
		roi->SetVisibility(und);

		for (LegoU32 i = 0; i < p_node->GetNumChildren(); i++) {
			FUN_100a8e80(p_node->GetChild(i), roi->m_local2world, p_time, p_roiMap);
		}
	}
	else {
		MxMatrix local2world;
		local2world.Product(mat, p_matrix);

		for (LegoU32 i = 0; i < p_node->GetNumChildren(); i++) {
			FUN_100a8e80(p_node->GetChild(i), local2world, p_time, p_roiMap);
		}
	}
}

// FUNCTION: LEGO1 0x100a8fd0
// FUNCTION: BETA10 0x1018ac81
void LegoROI::FUN_100a8fd0(LegoTreeNode* p_node, Matrix4& p_matrix, LegoTime p_time, LegoROI** p_roiMap)
{
	MxMatrix mat;

	LegoAnimNodeData* data = (LegoAnimNodeData*) p_node->GetData();
	FUN_100a8cb0(data, p_time, mat);

	LegoROI* roi = p_roiMap[data->GetUnknown0x20()];
	if (roi != NULL) {
		roi->m_local2world.Product(mat, p_matrix);

		for (LegoU32 i = 0; i < p_node->GetNumChildren(); i++) {
			FUN_100a8fd0(p_node->GetChild(i), roi->m_local2world, p_time, p_roiMap);
		}
	}
	else {
		MxMatrix local2world;
		local2world.Product(mat, p_matrix);

		for (LegoU32 i = 0; i < p_node->GetNumChildren(); i++) {
			FUN_100a8fd0(p_node->GetChild(i), local2world, p_time, p_roiMap);
		}
	}
}

// FUNCTION: LEGO1 0x100a90f0
LegoResult LegoROI::SetFrame(LegoAnim* p_anim, LegoTime p_time)
{
	LegoTreeNode* root = p_anim->GetRoot();
	MxMatrix mat;

	mat = m_local2world;
	mat.SetIdentity();

	return FUN_100a8da0(root, mat, p_time, this);
}

// FUNCTION: LEGO1 0x100a9170
// FUNCTION: BETA10 0x1018ae09
LegoResult LegoROI::FUN_100a9170(LegoFloat p_red, LegoFloat p_green, LegoFloat p_blue, LegoFloat p_alpha)
{
	LegoResult result = SUCCESS;
	CompoundObject::iterator it;

	int lodCount = GetLODCount();
	for (LegoU32 i = 0; i < lodCount; i++) {
		LegoLOD* lod = (LegoLOD*) GetLOD(i);

		if (lod->FUN_100aacb0(p_red, p_green, p_blue, p_alpha) != SUCCESS) {
			result = FAILURE;
		}
	}

	if (comp != NULL) {
		for (it = comp->begin(); it != comp->end(); it++) {
			if (((LegoROI*) *it)->FUN_100a9170(p_red, p_green, p_blue, p_alpha) != SUCCESS) {
				result = FAILURE;
			}
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100a9210
LegoResult LegoROI::FUN_100a9210(LegoTextureInfo* p_textureInfo)
{
	LegoResult result = SUCCESS;
	CompoundObject::iterator it;

	int lodCount = GetLODCount();
	for (LegoU32 i = 0; i < lodCount; i++) {
		LegoLOD* lod = (LegoLOD*) GetLOD(i);

		if (lod->FUN_100aad00(p_textureInfo) != SUCCESS) {
			result = FAILURE;
		}
	}

	if (comp != NULL) {
		for (it = comp->begin(); it != comp->end(); it++) {
			if (((LegoROI*) *it)->FUN_100a9210(p_textureInfo) != SUCCESS) {
				result = FAILURE;
			}
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100a92a0
// FUNCTION: BETA10 0x1018b12d
LegoResult LegoROI::GetTexture(LegoTextureInfo*& p_textureInfo)
{
	CompoundObject::iterator it;

	int lodCount = GetLODCount();
	for (LegoU32 i = 0; i < lodCount; i++) {
		LegoLOD* lod = (LegoLOD*) GetLOD(i);

		if (lod->GetTexture(p_textureInfo) == SUCCESS) {
			return SUCCESS;
		}
	}

	if (comp != NULL) {
		for (it = comp->begin(); it != comp->end(); it++) {
			if (((LegoROI*) *it)->GetTexture(p_textureInfo) == SUCCESS) {
				return SUCCESS;
			}
		}
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x100a9330
// FUNCTION: BETA10 0x1018b22c
LegoResult LegoROI::FUN_100a9330(LegoFloat p_red, LegoFloat p_green, LegoFloat p_blue, LegoFloat p_alpha)
{
	return FUN_100a9170(p_red, p_green, p_blue, p_alpha);
}

// FUNCTION: LEGO1 0x100a9350
// FUNCTION: BETA10 0x1018b25c
LegoResult LegoROI::FUN_100a9350(const LegoChar* p_color)
{
	MxFloat red, green, blue, alpha;
	if (ColorAliasLookup(p_color, red, green, blue, alpha)) {
		return FUN_100a9170(red, green, blue, alpha);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100a93b0
// FUNCTION: BETA10 0x1018b2c0
LegoResult LegoROI::FUN_100a93b0(const LegoChar* p_color)
{
	MxFloat red, green, blue, alpha;
	if (ColorAliasLookup(p_color, red, green, blue, alpha)) {
		return FUN_100a9330(red, green, blue, alpha);
	}

	return 0;
}

// FUNCTION: LEGO1 0x100a9410
// FUNCTION: BETA10 0x1018b324
LegoU32 LegoROI::FUN_100a9410(
	Vector3& p_v1,
	Vector3& p_v2,
	float p_f1,
	float p_f2,
	Vector3& p_v3,
	LegoBool p_collideBox
)
{
	if (p_collideBox) {
		Mx3DPointFloat v2(p_v2);
		v2 *= p_f1;
		v2 += p_v1;

		Mx4DPointFloat localc0;
		Mx4DPointFloat local9c;
		Mx4DPointFloat local168;
		Mx4DPointFloat local70;
		Mx4DPointFloat local150[6];

		Vector3 local58(&localc0[0]);
		Vector3 locala8(&local9c[0]);
		Vector3 local38(&local168[0]);

		Mx3DPointFloat local4c(p_v1);

		local58 = m_unk0x80.Min();
		locala8 = m_unk0x80.Max();

		localc0[3] = local9c[3] = local168[3] = 1.0f;

		local38 = local58;
		local38 += locala8;
		local38 *= 0.5f;

		local70 = localc0;
		localc0.SetMatrixProduct(&local70, (float*) m_local2world.GetData());

		local70 = local9c;
		local9c.SetMatrixProduct(&local70, (float*) m_local2world.GetData());

		local70 = local168;
		local168.SetMatrixProduct(&local70, (float*) m_local2world.GetData());

		p_v3 = m_local2world[3];

		LegoS32 i;
		for (i = 0; i < 6; i++) {
			local150[i] = m_local2world[i % 3];

			if (i > 2) {
				local150[i][3] = -local58.Dot(&local58, &local150[i]);
			}
			else {
				local150[i][3] = -locala8.Dot(&locala8, &local150[i]);
			}

			if (local150[i][3] + local38.Dot(&local38, &local150[i]) < 0.0f) {
				local150[i] *= -1.0f;
			}
		}

		for (i = 0; i < 6; i++) {
			float local50 = p_v2.Dot(&p_v2, &local150[i]);

			if (local50 >= 0.01 || local50 < -0.01) {
				local50 = -((local150[i][3] + local4c.Dot(&local4c, &local150[i])) / local50);

				if (local50 >= 0.0f && local50 <= p_f1) {
					Mx3DPointFloat local17c(p_v2);
					local17c *= local50;
					local17c += local4c;

					LegoS32 j;
					for (j = 0; j < 6; j++) {
						if (i != j && i - j != 3 && j - i != 3) {
							if (local150[j][3] + local17c.Dot(&local17c, &local150[j]) < 0.0f) {
								break;
							}
						}
					}

					if (j == 6) {
						return 1;
					}
				}
			}
		}
	}
	else {
		Mx3DPointFloat v1(p_v1);
		v1 -= GetWorldBoundingSphere().Center();

		float local10 = GetWorldBoundingSphere().Radius();
		float local8 = p_v2.Dot(&p_v2, &p_v2);
		float localc = p_v2.Dot(&p_v2, &v1) * 2.0f;
		float local14 = v1.Dot(&v1, &v1) - (local10 * local10);

		if (local8 >= 0.001 || local8 <= -0.001) {
			float local1c = -1.0f;
			float local18 = (localc * localc) - (local14 * local8 * 4.0f);

			if (local18 >= -0.001) {
				local8 *= 2.0f;
				localc = -localc;

				if (local18 > 0.0f) {
					local18 = sqrt(local18);
					float local184 = (localc + local18) / local8;
					float local188 = (localc - local18) / local8;

					if (local184 > 0.0f && local188 > local184) {
						local1c = local184;
					}
					else if (local188 > 0.0f) {
						local1c = local188;
					}
					else {
						return 0;
					}
				}
				else {
					local1c = localc / local8;
				}

				if (local1c >= 0.0f && p_f1 >= local1c) {
					p_v3 = p_v2;
					p_v3 *= local1c;
					p_v3 += p_v1;
					return 1;
				}
			}
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x100a9a50
TimeROI::TimeROI(Tgl::Renderer* p_renderer, ViewLODList* p_lodList, LegoTime p_time) : LegoROI(p_renderer, p_lodList)
{
	m_time = p_time;
}

// FUNCTION: LEGO1 0x100a9b40
void TimeROI::FUN_100a9b40(Matrix4& p_matrix, LegoTime p_time)
{
	LegoTime time = p_time - m_time;

	if (time) {
		m_time = p_time;

		Mx3DPointFloat targetPosition(p_matrix[3]);
		Vector3 vec(m_local2world[3]);

		targetPosition -= vec;
		targetPosition /= time * 0.001;

		FUN_100a5a30(targetPosition);
	}
}

// FUNCTION: LEGO1 0x100a9bf0
LegoBool LegoROI::FUN_100a9bf0(const LegoChar* p_param, float& p_red, float& p_green, float& p_blue, float& p_alpha)
{
	if (p_param == NULL) {
		return FALSE;
	}

	if (g_unk0x101013ac) {
		char buf[32];
		if (g_unk0x101013ac(p_param, buf, sizeof(buf))) {
			p_param = buf;
		}
	}

	return ColorAliasLookup(p_param, p_red, p_green, p_blue, p_alpha);
}

// FUNCTION: LEGO1 0x100a9c50
// FUNCTION: BETA10 0x1018bdd9
LegoBool LegoROI::ColorAliasLookup(const LegoChar* p_param, float& p_red, float& p_green, float& p_blue, float& p_alpha)
{
	for (LegoU32 i = 0; i < sizeOfArray(g_roiColorAliases); i++) {
		if (strcmpi(g_roiColorAliases[i].m_name, p_param) == 0) {
			p_red = g_roiColorAliases[i].m_red / 255.0;
			p_green = g_roiColorAliases[i].m_green / 255.0;
			p_blue = g_roiColorAliases[i].m_blue / 255.0;
			p_alpha = g_roiColorAliases[i].m_alpha / 255.0;
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x100a9cf0
LegoBool LegoROI::FUN_100a9cf0(const LegoChar* p_param, unsigned char* paletteEntries, LegoU32 p_numEntries)
{
	if (p_param == NULL) {
		return FALSE;
	}

	if (g_unk0x101013b0 != NULL) {
		return g_unk0x101013b0(p_param, paletteEntries, p_numEntries);
	}

	paletteEntries[0] = '\0';
	return FALSE;
}

// FUNCTION: LEGO1 0x100a9d30
void LegoROI::FUN_100a9d30(ROIHandler p_func)
{
	g_unk0x101013ac = p_func;
}

// FUNCTION: LEGO1 0x100a9d40
void LegoROI::SetName(const LegoChar* p_name)
{
	if (m_name != NULL) {
		delete[] m_name;
	}

	if (p_name != NULL) {
		m_name = new LegoChar[strlen(p_name) + 1];
		strcpy(m_name, p_name);
		strlwr(m_name);
	}
	else {
		m_name = NULL;
	}
}

// FUNCTION: LEGO1 0x100a9dd0
// FUNCTION: BETA10 0x1018bfdb
void LegoROI::FUN_100a9dd0()
{
	int lodCount = GetLODCount();
	for (LegoS32 i = 0; i < lodCount; i++) {
		LegoLOD* lod = (LegoLOD*) GetLOD(i);
		lod->FUN_100aae60();
	}
}

// FUNCTION: LEGO1 0x100a9e10
void LegoROI::SetDisplayBB(int p_displayBB)
{
	// Intentionally empty function
}

// FUNCTION: LEGO1 0x100aa340
float LegoROI::IntrinsicImportance() const
{
	return .5;
}

// FUNCTION: LEGO1 0x100aa350
void LegoROI::UpdateWorldBoundingVolumes()
{
	CalcWorldBoundingVolumes(m_sphere, m_local2world, m_world_bounding_box, m_world_bounding_sphere);
}
