// no, there is no typo in this file. the actual name of the class is TowTrack. 
// presumably the developers made a typo when trying to name it "TowTruck" and 
// just went with it, but that doesn't really make sense because there is also 
// TowTrackMissionState, which has this same oddity. was it a joke? regional
// dialect? or maybe they just didn't have spellcheck? we may never know

#include "towtrack.h"

// OFFSET: LEGO1 0x1004c7c0
const char* TowTrack::GetClassName() {
    return "TowTrack";
}