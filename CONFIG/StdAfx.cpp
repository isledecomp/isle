// stdafx.cpp : source file that includes just the standard includes
//	simple.pch will be the pre-compiled header
//	stdafx.obj will contain the pre-compiled type information

#include "stdafx.h"

// This is the one translation unit that defines the DirectX GUIDs, so none of
// them have to come out of dxguid.lib. The order below is significant:
// initguid.h needs objbase.h to have provided DEFINE_GUID, it must precede the
// DirectX headers whose GUIDs are being defined, and dsound.h needs
// WAVEFORMATEX from mmsystem.h.
// clang-format off
#include <objbase.h>
#include <initguid.h>
#include <mmsystem.h>

#include <ddraw.h>
#include <dinput.h>
#include <dsound.h>
// clang-format on
