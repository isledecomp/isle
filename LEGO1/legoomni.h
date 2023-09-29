#ifndef LEGOOMNI_H
#define LEGOOMNI_H

#include "compat.h"
#include "legoentity.h"
#include "legoinputmanager.h"
#include "legogamestate.h"
#include "legonavcontroller.h"
#include "legopathboundary.h"
#include "legoroi.h"
#include "legovideomanager.h"
#include "mxatomid.h"
#include "mxbackgroundaudiomanager.h"
#include "mxdsaction.h"
#include "mxdsfile.h"
#include "mxdsobject.h"
#include "mxomni.h"
#include "mxtransitionmanager.h"
#include "isle.h"
#include "legobuildingmanager.h"
#include "legoplantmanager.h"

class LegoSoundManager;
class MxTransitionManager;

// VTABLE 0x100d8638
// SIZE: 0x140
class LegoOmni : public MxOmni
{
public:
  __declspec(dllexport) void CreateBackgroundAudio();
  __declspec(dllexport) void RemoveWorld(const MxAtomId &p1, MxLong p2);
  __declspec(dllexport) static int GetCurrPathInfo(LegoPathBoundary **,int &);
  __declspec(dllexport) static void CreateInstance();
  __declspec(dllexport) static LegoOmni *GetInstance();

  LegoOmni();
  virtual ~LegoOmni(); // vtable+00

  virtual MxLong Notify(MxParam &p) override; // vtable+04

  // OFFSET: LEGO1 0x10058aa0
  inline virtual const char *ClassName() const override // vtable+0c
  {
    // 0x100f671c
    return "LegoOmni";
  }

  // OFFSET: LEGO1 0x10058ab0
  inline virtual MxBool IsA(const char *name) const override // vtable+10
  {
    return !strcmp(name, LegoOmni::ClassName()) || MxOmni::IsA(name);
  }

  virtual void Init() override; // vtable+14
  virtual MxResult Create(COMPAT_CONST MxOmniCreateParam &p) override; // vtable+18
  virtual void Destroy() override; // vtable+1c
  virtual void vtable0x20() override;
  virtual void DeleteObject(MxDSAction &ds) override;
  virtual MxBool DoesEntityExist(MxDSAction &ds) override;
  virtual void vtable0x2c() override;
  virtual int vtable0x30(char*, int, MxCore*) override;
  virtual void NotifyCurrentEntity() override;
  virtual void StartTimer() override;
  virtual void vtable0x3c() override;
  virtual MxBool vtable40();

  LegoVideoManager *GetVideoManager() { return (LegoVideoManager *) m_videoManager; }
  LegoSoundManager *GetSoundManager() { return (LegoSoundManager *)m_soundManager;}
  MxBackgroundAudioManager *GetBackgroundAudioManager() { return m_bkgAudioManager; }
  LegoInputManager *GetInputManager() { return m_inputMgr; }
  Isle *GetIsle() { return m_isle; }
  LegoBuildingManager *GetLegoBuildingManager() { return m_buildingManager; }
  LegoPlantManager *GetLegoPlantManager() { return m_plantManager; }
  LegoGameState *GetGameState() { return m_gameState; }
  LegoNavController *GetNavController() { return m_navController; }
  MxTransitionManager *GetTransitionManager() { return m_transitionManager; }

private:
  int m_unk68;
  int m_unk6c;
  LegoInputManager *m_inputMgr; // 0x70
  char m_unk74[0x10];
  LegoNavController *m_navController; // 0x84
  Isle* m_isle; // 0x88
  char m_unk8c[0x4];
  LegoPlantManager* m_plantManager; // 0x90
  char m_unk94[0x4];
  LegoBuildingManager* m_buildingManager; // 0x98
  LegoGameState *m_gameState; // 0x9c
  MxDSAction m_action;
  MxBackgroundAudioManager *m_bkgAudioManager; // 0x134
  MxTransitionManager *m_transitionManager; // 0x138
  int m_unk13c;

};

__declspec(dllexport) MxBackgroundAudioManager * BackgroundAudioManager();
__declspec(dllexport) MxDSObject * CreateStreamObject(MxDSFile *,MxS16);
__declspec(dllexport) LegoGameState * GameState();
__declspec(dllexport) const char * GetNoCD_SourceName();
__declspec(dllexport) LegoInputManager * InputManager();
__declspec(dllexport) LegoOmni * Lego();
__declspec(dllexport) void MakeSourceName(char *, const char *);
__declspec(dllexport) LegoEntity * PickEntity(MxLong,MxLong);
__declspec(dllexport) LegoROI * PickROI(MxLong,MxLong);
__declspec(dllexport) void SetOmniUserMessage(void (*)(const char *,int));
__declspec(dllexport) LegoSoundManager * SoundManager();
__declspec(dllexport) MxLong Start(MxDSAction *);
__declspec(dllexport) MxTransitionManager * TransitionManager();
__declspec(dllexport) LegoVideoManager * VideoManager();
__declspec(dllexport) MxLong Start(MxDSAction *a);

LegoBuildingManager* BuildingManager();
Isle* GetIsle();
LegoPlantManager* PlantManager();
MxBool KeyValueStringParse(char *, const char *, const char *);

#endif // LEGOOMNI_H
