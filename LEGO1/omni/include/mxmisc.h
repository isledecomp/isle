#ifndef MXMISC_H
#define MXMISC_H

#include "mxtypes.h"

class MxAtomIdCounterSet;
class MxDSAction;
class MxEventManager;
class MxMusicManager;
class MxNotificationManager;
class MxObjectFactory;
class MxSoundManager;
class MxStreamer;
class MxTickleManager;
class MxTimer;
class MxVariableTable;
class MxVideoManager;

MxTickleManager* TickleManager();
MxTimer* Timer();
MxStreamer* Streamer();
MxSoundManager* MSoundManager();
MxVariableTable* VariableTable();
MxMusicManager* MusicManager();
MxEventManager* EventManager();
MxResult Start(MxDSAction*);
MxNotificationManager* NotificationManager();
MxVideoManager* MVideoManager();
MxAtomIdCounterSet* AtomIdCounterSet();
MxObjectFactory* ObjectFactory();
void DeleteObject(MxDSAction& p_dsAction);

#endif // MXMISC_H
