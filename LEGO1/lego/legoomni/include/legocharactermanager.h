#ifndef LEGOCHARACTERMANAGER_H
#define LEGOCHARACTERMANAGER_H

#include "decomp.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"
#include "roi/legoroi.h"

class CustomizeAnimFileVariable;
class LegoActor;
class LegoExtraActor;
class LegoStorage;
class LegoROI;

#pragma warning(disable : 4237)

struct LegoCharacterComparator {
	MxBool operator()(const char* const& p_a, const char* const& p_b) const { return strcmpi(p_a, p_b) < 0; }
};

// SIZE 0x08
struct LegoCharacter {
	LegoCharacter(LegoROI* p_roi)
	{
		m_roi = p_roi;
		m_refCount = 1;
	}
	~LegoCharacter() { delete m_roi; }

	void AddRef() { m_refCount++; }
	MxU32 RemoveRef()
	{
		if (m_refCount != 0) {
			m_refCount--;
		}

		return m_refCount;
	}

	LegoROI* m_roi;   // 0x00
	MxU32 m_refCount; // 0x04
};

struct LegoActorInfo;

typedef map<char*, LegoCharacter*, LegoCharacterComparator> LegoCharacterMap;

// SIZE 0x08
class LegoCharacterManager {
public:
	LegoCharacterManager();
	~LegoCharacterManager();

	MxResult Write(LegoStorage* p_storage);
	MxResult Read(LegoStorage* p_storage);
	const char* GetActorName(MxS32 p_index);
	MxU32 GetNumActors();
	LegoROI* GetActorROI(const char* p_name, MxBool p_createEntity);

	void Init();
	static void SetCustomizeAnimFile(const char* p_value);
	static MxBool IsActor(const char* p_name);

	void ReleaseAllActors();
	MxBool Exists(const char* p_name);
	MxU32 GetRefCount(LegoROI* p_roi);
	void ReleaseActor(const char* p_name);
	void ReleaseActor(LegoROI* p_roi);
	void ReleaseAutoROI(LegoROI* p_roi);
	MxBool FUN_100849a0(LegoROI* p_roi, LegoTextureInfo* p_textureInfo);
	LegoExtraActor* GetExtraActor(const char* p_name);
	LegoActorInfo* GetActorInfo(const char* p_name);
	LegoActorInfo* GetActorInfo(LegoROI* p_roi);
	MxBool SwitchColor(LegoROI* p_roi, LegoROI* p_targetROI);
	MxBool SwitchVariant(LegoROI* p_roi);
	MxBool SwitchSound(LegoROI* p_roi);
	MxBool SwitchMove(LegoROI* p_roi);
	MxBool SwitchMood(LegoROI* p_roi);
	MxU32 GetAnimationId(LegoROI* p_roi);
	MxU32 GetSoundId(LegoROI* p_roi, MxBool p_und);
	MxU8 GetMood(LegoROI* p_roi);
	LegoROI* CreateAutoROI(const char* p_name, const char* p_lodName, MxBool p_createEntity);
	MxResult FUN_10085870(LegoROI* p_roi);
	LegoROI* FUN_10085a80(const char* p_name, const char* p_lodName, MxBool p_createEntity);

	static const char* GetCustomizeAnimFile() { return g_customizeAnimFile; }

private:
	LegoROI* CreateActorROI(const char* p_key);
	void RemoveROI(LegoROI* p_roi);
	LegoROI* FindChildROI(LegoROI* p_roi, const char* p_name);

	static char* g_customizeAnimFile;
	static MxU32 g_maxMove;
	static MxU32 g_maxSound;

	LegoCharacterMap* m_characters;                 // 0x00
	CustomizeAnimFileVariable* m_customizeAnimFile; // 0x04
};

// clang-format off
// TEMPLATE: LEGO1 0x1001a690
// list<ROI *,allocator<ROI *> >::_Buynode

// TEMPLATE: LEGO1 0x10035790
// ?_Construct@@YAXPAPAVROI@@ABQAV1@@Z

// TEMPLATE: LEGO1 0x10082b90
// _Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::~_Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >

// TEMPLATE: LEGO1 0x10082c60
// _Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::iterator::_Inc

// TEMPLATE: LEGO1 0x10082ca0
// _Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::erase

// TEMPLATE: LEGO1 0x100830f0
// _Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::_Erase

// TEMPLATE: LEGO1 0x10083130
// map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::~map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >

// TEMPLATE: LEGO1 0x10083840
// _Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::iterator::_Dec

// TEMPLATE: LEGO1 0x10083890
// _Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::_Insert

// TEMPLATE: LEGO1 0x10085500
// _Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::insert

// TEMPLATE: LEGO1 0x10085790
// _Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::_Buynode

// TEMPLATE: LEGO1 0x100857b0
// _Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::_Lrotate

// TEMPLATE: LEGO1 0x10085810
// _Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::_Rrotate

// GLOBAL: LEGO1 0x100fc508
// _Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::_Nil
// clang-format on

#endif // LEGOCHARACTERMANAGER_H
