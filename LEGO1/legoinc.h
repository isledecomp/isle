#ifndef LEGOINC_H
#define LEGOINC_H

// It is recommended to include this over <windows.h> directly because this way
// we can undef stuff that might cause issues with our code.

#include <windows.h>
#undef GetClassName

#endif // LEGOINC_H
