#ifndef LEGOOMNI_H
#define LEGOOMNI_H

#include "mxbackgroundaudiomanager.h"
#include "mxdsaction.h"
#include "mxdsfile.h"
#include "mxdsobject.h"
#include "mxomnicreateparam.h"
#include "mxresult.h"
#include "mxstreamer.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "mxtransitionmanager.h"
#include "legoanimationmanager.h"
#include "legobuildingmanager.h"
#include "legoentity.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legomodelpresenter.h"
#include "legopartpresenter.h"
#include "legoroi.h"
#include "legoworldpresenter.h"
#include "legovideomanager.h"

class LegoSoundManager;
class MxEventManager;
class MxMusicManager;
class MxNotificationManager;
class MxSoundManager;

// class LegoOmni : public MxOmni
class LegoOmni
{
public:
  __declspec(dllexport) void CreateBackgroundAudio();
  __declspec(dllexport) void RemoveWorld(const MxAtomId &p1, long p2);
  __declspec(dllexport) static int GetCurrPathInfo(class LegoPathBoundary * *,int &);
  __declspec(dllexport) static void CreateInstance();
  __declspec(dllexport) static LegoOmni *GetInstance();

  virtual ~LegoOmni();

  virtual void vtable04();
  virtual void vtable08();
  virtual void vtable0c();
  virtual void vtable10();
  virtual void vtable14();
  virtual MxResult Create(const MxOmniCreateParam &p);
  virtual void vtable1c();
  virtual void vtable20();
  virtual void vtable24(MxDSAction &ds);
  virtual MxBool vtable28(MxDSAction &ds);
  virtual void vtable2c();
  virtual void vtable30();
  virtual void vtable34();
  virtual void vtable38();
  virtual void vtable3c();
  virtual unsigned char vtable40();

  LegoVideoManager *GetVideoManager() { return m_videoMgr; }
  LegoInputManager *GetInputManager() { return m_inputMgr; }

private:
  int m_unk04;
  int m_unk08;
  int m_unk0c;
  int m_unk10;
  int m_unk14;
  int m_unk18;
  int m_unk1c;
  int m_unk20;
  int m_unk24;
  int m_unk28;
  LegoVideoManager *m_videoMgr;
  int m_unk30;
  int m_unk34;
  int m_unk38;
  int m_unk3c;
  int m_unk40;
  int m_unk44;
  int m_unk48;
  int m_unk4c;
  int m_unk50;
  int m_unk54;
  int m_unk58;
  int m_unk5c;
  int m_unk60;
  int m_unk64;
  int m_unk68;
  int m_unk6c;
  LegoInputManager *m_inputMgr;

  static LegoOmni *m_instance;

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
__declspec(dllexport) MxTimer * Timer();
__declspec(dllexport) MxTransitionManager * TransitionManager();
__declspec(dllexport) MxVariableTable * VariableTable();
__declspec(dllexport) LegoVideoManager * VideoManager();

__declspec(dllexport) long Start(MxDSAction *a);

#endif // LEGOOMNI_H
