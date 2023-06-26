#ifndef LEGOOMNI_H
#define LEGOOMNI_H

#include "legoentity.h"
#include "legoinputmanager.h"
#include "legogamestate.h"
#include "legonavcontroller.h"
#include "legoroi.h"
#include "legovideomanager.h"
#include "mxatomid.h"
#include "mxbackgroundaudiomanager.h"
#include "mxdsaction.h"
#include "mxdsfile.h"
#include "mxdsobject.h"
#include "mxomni.h"
#include "mxtransitionmanager.h"

class LegoSoundManager;

class LegoOmni : public MxOmni
{
public:
  __declspec(dllexport) void CreateBackgroundAudio();
  __declspec(dllexport) void RemoveWorld(const MxAtomId &p1, long p2);
  __declspec(dllexport) static int GetCurrPathInfo(class LegoPathBoundary * *,int &);
  __declspec(dllexport) static void CreateInstance();
  __declspec(dllexport) static LegoOmni *GetInstance();

  LegoOmni();
  virtual ~LegoOmni(); // vtable+00

  virtual long Notify(MxParam &p); // vtable+04

  // OFFSET: LEGO1 0x10058aa0
  inline virtual const char *GetClassName() const { return "LegoOmni"; }; // vtable+0c

  // OFFSET: LEGO1 0x10058ab0
  inline virtual MxBool IsClass(const char *name) const {
    return !strcmp(name, LegoOmni::GetClassName()) || MxOmni::IsClass(name);
  }; // vtable+10;

  virtual void Init(); // vtable+14
  virtual MxResult Create(MxOmniCreateParam &p); // vtable+18
  virtual void Destroy(); // vtable+1c
  virtual void vtable20();
  virtual void vtable24(MxDSAction &ds);
  virtual MxBool vtable28(MxDSAction &ds);
  virtual void vtable2c();
  virtual void vtable30();
  virtual void vtable34();
  virtual void vtable38();
  virtual void vtable3c();
  virtual unsigned char vtable40();

  LegoVideoManager *GetVideoManager() { return (LegoVideoManager *) m_videoManager; }
  LegoSoundManager *GetSoundManager() { return (LegoSoundManager *)m_soundManager;}
  MxBackgroundAudioManager *GetBackgroundAudioManager() { return m_bkgAudioManager; }
  LegoInputManager *GetInputManager() { return m_inputMgr; }
  LegoGameState *GetGameState() { return m_gameState; }
  LegoNavController *GetNavController() { return m_navController; }

private:
  int m_unk68;
  int m_unk6c;
  LegoInputManager *m_inputMgr; // 0x70
  char m_unk74[0x10];
  LegoNavController *m_navController; // 0x84
  char m_unk88[0x14];
  LegoGameState *m_gameState; // 0x9c
  char m_unka0[0x94];
  MxBackgroundAudioManager *m_bkgAudioManager; // 0x134
  MxTransitionManager *m_transitionManager; // 0x138

};

__declspec(dllexport) MxBackgroundAudioManager * BackgroundAudioManager();
__declspec(dllexport) MxDSObject * CreateStreamObject(MxDSFile *,short);
__declspec(dllexport) MxEventManager * EventManager();
__declspec(dllexport) LegoGameState * GameState();
__declspec(dllexport) const char * GetNoCD_SourceName();
__declspec(dllexport) LegoInputManager * InputManager();
__declspec(dllexport) LegoOmni * Lego();
__declspec(dllexport) MxSoundManager * MSoundManager();
__declspec(dllexport) void MakeSourceName(char *, const char *);
__declspec(dllexport) MxMusicManager * MusicManager();
__declspec(dllexport) MxNotificationManager * NotificationManager();
__declspec(dllexport) LegoEntity * PickEntity(long,long);
__declspec(dllexport) LegoROI * PickROI(long,long);
__declspec(dllexport) void SetOmniUserMessage(void (*)(const char *,int));
__declspec(dllexport) LegoSoundManager * SoundManager();
__declspec(dllexport) long Start(MxDSAction *);
__declspec(dllexport) MxStreamer * Streamer();
__declspec(dllexport) MxTickleManager * TickleManager();
__declspec(dllexport) MxTransitionManager * TransitionManager();
__declspec(dllexport) MxVariableTable * VariableTable();
__declspec(dllexport) LegoVideoManager * VideoManager();

__declspec(dllexport) long Start(MxDSAction *a);

#endif // LEGOOMNI_H
