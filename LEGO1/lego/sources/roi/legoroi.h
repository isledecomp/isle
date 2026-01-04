#ifndef LEGOROI_H
#define LEGOROI_H

#include "misc/legotypes.h"
#include "viewmanager/viewroi.h"

typedef unsigned char (*ColorOverride)(const char*, char*, unsigned int);
typedef unsigned char (*TextureHandler)(const char*, unsigned char*, unsigned int);

class LegoEntity;
class LegoTextureContainer;
class LegoTextureInfo;
class LegoStorage;
class LegoAnim;
class LegoAnimNodeData;
class LegoTreeNode;
struct LegoAnimActorEntry;

// VTABLE: LEGO1 0x100dbe38
// VTABLE: BETA10 0x101c3898
// SIZE 0x108
class LegoROI : public ViewROI {
public:
	LegoROI(Tgl::Renderer* p_renderer);
	LegoROI(Tgl::Renderer* p_renderer, ViewLODList* p_lodList);
	~LegoROI() override;

	LegoResult Read(
		OrientableROI* p_parentROI,
		Tgl::Renderer* p_renderer,
		ViewLODListManager* p_viewLODListManager,
		LegoTextureContainer* p_textureContainer,
		LegoStorage* p_storage
	);
	LegoROI* FindChildROI(const LegoChar* p_name, LegoROI* p_roi);
	LegoResult ApplyChildAnimationTransformation(
		LegoTreeNode* p_node,
		const Matrix4& p_matrix,
		LegoTime p_time,
		LegoROI* p_roi
	);
	static void ApplyAnimationTransformation(
		LegoTreeNode* p_node,
		Matrix4& p_matrix,
		LegoTime p_time,
		LegoROI** p_roiMap
	);
	static void ApplyTransform(LegoTreeNode* p_node, Matrix4& p_matrix, LegoTime p_time, LegoROI** p_roiMap);
	LegoResult SetFrame(LegoAnim* p_anim, LegoTime p_time);
	LegoResult SetLodColor(LegoFloat p_red, LegoFloat p_green, LegoFloat p_blue, LegoFloat p_alpha);
	LegoResult SetTextureInfo(LegoTextureInfo* p_textureInfo);
	LegoResult GetTextureInfo(LegoTextureInfo*& p_textureInfo);
	LegoResult FUN_100a9330(LegoFloat p_red, LegoFloat p_green, LegoFloat p_blue, LegoFloat p_alpha);
	LegoResult SetLodColor(const LegoChar* p_name);
	LegoResult FUN_100a93b0(const LegoChar* p_name);
	LegoU32 Intersect(Vector3& p_v1, Vector3& p_v2, float p_f1, float p_f2, Vector3& p_v3, LegoBool p_collideBox);
	void SetName(const LegoChar* p_name);

	float IntrinsicImportance() const override; // vtable+0x04
	void UpdateWorldBoundingVolumes() override; // vtable+0x18

	void ClearMeshOffset();
	void SetDisplayBB(int p_displayBB);

	static LegoResult CreateLocalTransform(LegoAnimNodeData* p_data, LegoTime p_time, Matrix4& p_matrix);
	static void FUN_100a81b0(const LegoChar* p_error, ...);
	static void configureLegoROI(int p_roi);
	static void SetColorOverride(ColorOverride p_colorOverride);
	static LegoBool GetRGBAColor(const LegoChar* p_name, float& p_red, float& p_green, float& p_blue, float& p_alpha);
	static LegoBool ColorAliasLookup(
		const LegoChar* p_param,
		float& p_red,
		float& p_green,
		float& p_blue,
		float& p_alpha
	);
	static LegoBool GetPaletteEntries(const LegoChar* p_name, unsigned char* paletteEntries, LegoU32 p_numEntries);

	// FUNCTION: BETA10 0x1000f320
	const LegoChar* GetName() const { return m_name; }

	// FUNCTION: BETA10 0x10015180
	LegoEntity* GetEntity() { return m_entity; }

	BoundingSphere& GetBoundingSphere() { return m_sphere; }

	// FUNCTION: BETA10 0x10013400
	void SetEntity(LegoEntity* p_entity) { m_entity = p_entity; }

	void SetComp(CompoundObject* p_comp) { comp = p_comp; }
	void SetBoundingSphere(const BoundingSphere& p_sphere) { m_sphere = m_world_bounding_sphere = p_sphere; }
	void SetBoundingBox(const BoundingBox& p_box) { m_bounding_box = p_box; }

	// SYNTHETIC: LEGO1 0x100a82b0
	// SYNTHETIC: BETA10 0x1018c490
	// LegoROI::`scalar deleting destructor'

private:
	LegoChar* m_name;         // 0xe4
	BoundingSphere m_sphere;  // 0xe8
	LegoBool m_sharedLodList; // 0x100
	LegoEntity* m_entity;     // 0x104
};

// VTABLE: LEGO1 0x100dbea8
// VTABLE: BETA10 0x101c38d0
// SIZE 0x10c
class TimeROI : public LegoROI {
public:
	TimeROI(Tgl::Renderer* p_renderer, ViewLODList* p_lodList, LegoTime p_time);

	void CalculateWorldVelocity(Matrix4& p_matrix, LegoTime p_time);

	// SYNTHETIC: LEGO1 0x100a9ad0
	// SYNTHETIC: BETA10 0x1018c540
	// TimeROI::`scalar deleting destructor'

	// SYNTHETIC: BETA10 0x1018c580
	// TimeROI::~TimeROI

private:
	LegoTime m_time; // 0x108
};

#endif // LEGOROI_H
