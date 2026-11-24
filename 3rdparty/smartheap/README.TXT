Welcome to SmartHeap 3.31 for Win32!
-----------------------------------

This readme file contains important information about this
SmartHeap release.  It includes updates to the printed Programmer's
Guide, and other information not available elsewhere.

This release supports the Microsoft Visual C++ 2.x/4.x/5.0, and 
Borland C++ 4.x/5.0, compilers on Windows NT, Windows 95, and Win32s.



Table of Contents
-----------------
0.  New in this release
1.  Installation
2.  Important information
3.  Sample programs
4.  Evaluating SmartHeap performance
5.  Technical support


0. New in this release
----------------------

"Quick" setup procedure for Visual C++ Users
--------------------------------------------

See "Quick Setup" in the Getting Started Guide for
a simpler linking procedure that automatically selects
the appropriate SmartHeap libraries based on the compile-
time settings in your application's project.


Support for Visual C++ 5.0
--------------------------

SmartHeap 3.3 adds support for the Microsoft Visual C++ 
5.0 compiler.


Patching control API
--------------------

SmartHeap 3.3 introduces an API to control patching of heap
functions.  The new API allows the same control over patching
as the existing registry values described later in this readme
file under "Disabling SmartHeap DLL's automatic patching."

The primary purpose of the patching control API is to allow
dynamically-loaded DLLs that link with the SmartHeap DLL to
control patching in processes into which such DLLs are loaded.
The API is easier to use for such DLLs than an EXE-specific
registry setting since such DLLs are not specific to a particular
EXE.

The patching control API has the prototype:

__declspec(dllexport) MEM_PATCHING MEM_ENTRY 
   MemSetPatching(const char ***skipDLLs);

To use this API, you must define and export the above function
from your EXE or DLL.  The return value is a bitwise disjunction
of patching directives that control patching settings.  Specify
one or more of the following values in the return value:

	MEM_SKIP_PATCHING_THIS_DLL: skip patching of CRT heap routines
     in the current DLL or EXE

	MEM_DISABLE_SYSTEM_HEAP_PATCHING: disable patching of system
     heap APIs

	MEM_DISABLE_ALL_PATCHING: disable all patching

The flags MEM_DISABLE_SYSTEM_HEAP_PATCHING and 
MEM_DISABLE_ALL_PATCHING are process-wide global and can be 
specified only if patching has not already been performed in
the current process.  Hence, these two values can be returned 
only by an export from the process' EXE if SmartHeap is linked
into the EXE or from a DLL that is loaded by LoadLibrary if
SmartHeap is linked into the DLL but not already loaded before
the DLL is loaded.

The skipDLLs parameter allows you to specify a list of DLLs that
SmartHeap should skip when performing patching.  Assign to this 
pointer a NULL-terminated array of character strings.

The following is an example MemSetPatching function:

/* specify that patching should be skipped for the current DLL
 * and also for DLLs foo.dll and bar.dll
 */
__declspec(dllexport) MEM_PATCHING MEM_ENTRY 
   MemSetPatching(const char ***skipDLLs)
{
	static const char * dlls[] = { "foo.dll", "bar.dll", NULL };
	*skipDLLs = dlls;

	return MEM_SKIP_PATCHING_THIS_DLL;
}

Note that SmartHeap may call your MemSetPatching function before
your DLL has been initialized and before the C runtime has been
initialized.  Therefore, do not dynamically allocate memory or
call other CRT functions from your MemSetPatching routine.



Tracing facility introduced for SmartHeap's patching
----------------------------------------------------

SmartHeap 3.3 adds a diagnostic tracing facility that allows
you to see exactly which functions in which DLLs SmartHeap is
patching.  To enable this tracing facility, add the path of the
file you wish to send trace output to in the registry value named
"PatchTraceFile" in the following registry key:

  for Runtime SmartHeap, to enable tracing for all applications,
  use the registry key:

  "HKEY_LOCAL_MACHINE\Software\MicroQuill\SmartHeap"

  or to enable tracing only for a specific application, use the key:

  "HKEY_LOCAL_MACHINE\Software\MicroQuill\SmartHeap\Apps\<app-name>"

  where <app-name> is the full path of your app's EXE, using forward
  slashes ("/") as directory delimeters since the registry would
  interpret backslashes ("\") as keys.  For example, if your app's
  full path is "c:\apps\foo.exe" you would add the registry key:

  "HKEY_LOCAL_MACHINE\Software\MicroQuill\SmartHeap\Apps\c:/apps/foo.exe"

  For Debug SmartHeap, to enable tracing for all applications,
  use the registry key:

  "HKEY_LOCAL_MACHINE\Software\MicroQuill\HeapAgent"

  or to enable tracing only for a specific application, use the key:

  "HKEY_LOCAL_MACHINE\Software\MicroQuill\HeapAgent\Apps\<app-name>"




New API for managing user-supplied region of memory
---------------------------------------------------

SmartHeap 3.3 introduces the following new API for allocating within
a region of memory supplied by the caller:

MEM_POOL MemPoolInitRegion(void *addr, unsigned long size, unsigned flags);

- addr is an arbitrary address of a memory region the user has 
reserved within which SmartHeap is manage the pool's memory

- size is the size, in bytes, of this memory region

- flags can specify any flags currently supported by MemPoolInit, 
plus it implicitly includes a new flag, MEM_POOL_REGION

The supplied region must be reserved but need not be committed.  It 
can be either private or shared (mmap).  If it is is mmap, 
MEM_POOL_SHARED must be supplied with flags.  SH will commit/decommit 
sub-ranges of address space within the region to dynamically 
grow/shrink the pool based on allocation requests (SH will decommit 
only for private pools, as Win32 does not support decommiting 
portions of a mmap -- for this reason, the entire region should be 
initialially UNcommitted for mmap regions, since Win32 does support 
commit for portions of a mmap).

MemPoolInitRegion rounds addr up to the nearest 4K boundary and 
truncates size beginning at the next 64K boundary after addr to the
nearest 64K multiple; the head and tail of the region, if any, are not used 
so to avoid wasting memory, supply a 4K-aligned and 64K-granular region.

For example, if addr and size are specified as 0x02000800 and 1040K,
respectively, then addr will be rounded up to 0x02001000 and size 
truncated to 978K.

Supply MEM_POOL_SERIALIZE if serialization of heap calls is desired 
for the pool.  If MEM_POOL_SHARED is supplied, SH uses a mutex object, 
otherwise SH uses a critical section object.  MEM_POOL_SERIALIZE is 
*not* required nor implied if MEM_POOL_SHARED is supplied alone -- in 
this case, it is the user's responsibility to serlialize allocations 
from each process that maps the pool.

Each process that uses a pool, where MEM_POOL_SHARED is
supplied (either with or without MEM_POOL_SERIALIZE), except
the process that calls MemPoolInitRegion, must call
MemPoolAttachShared specifying the pool value and a NULL
name, before the process allocates or deallocates from the
pool.  This is necessary, so SmartHeap can maintain its per-process
list of pools accurately in each process that uses the pool.  Also, 
if MEM_POOL_SERIALIZE is indicated, this MemPoolAttachShared call
allows SmartHeap to open the pool's mutex object in each process
that accesses the pool.

MemPoolFree can be called on pools created by MemPoolInitRegion -- 
this will close mutex/critical section objects and, for private 
pools, decommit the entire address range.  The caller is responsible
for actually freeing the memory.

All SH APIs that accept MEM_POOL parameters are supported with 
MEM_POOL_REGION pools, including all Debug SH APIs.




New in SmartHeap 3.2
--------------------

Support for NT 4.0 and Visual C++ 4.2
-------------------------------------

SmartHeap 3.2 adds support for Windows NT 4.0 and
the Microsoft Visual C++ 4.2 compiler.


Multi-thread library versions
-----------------------------

It is no longer necessary to make any source code changes to your
multi-threaded app in order to use SmartHeap.  Simply link with
either sh?w32?t.lib instead of sh?w32?.lib.  Debug SmartHeap is 
always thread-safe so use haw32m.lib for both single-and 
multi-threaded apps.


LoadLibrary DLLs patched by SmartHeap DLL
-----------------------------------------

In SmartHeap 3.2, if your application dynamically loads DLLs such as
MFC, OWL, or CRT DLLs that export memory allocation functions, SmartHeap
will automatically patch those memory allocation functions.  In previous
SmartHeap releases, this auto-patching was implemented only for DLLs
implicitly linked with your application's EXE.



HeapAlloc, GlobalAlloc, and LocalAlloc APIs implemented by SmartHeap DLL
------------------------------------------------------------------------

SmartHeap 3.2 adds support for the Win32 memory allocation APIs.  These
APIs are replaced by the SmartHeap DLL only, not by the statically-linked
SmartHeap library.  These APIs are replaced on Windows NT only, not on
Windows 95.

To disable patching of Win32 APIs, add the following registry value:

  for Runtime SmartHeap, add the DWORD registry key:
  "HKEY_LOCAL_MACHINE\Software\MicroQuill\SmartHeap\Apps\<app-name>"

  for Debug SmartHeap, add the DWORD registry value:
  "HKEY_LOCAL_MACHINE\Software\MicroQuill\HeapAgent\Apps\<app-name>"

  where <app-name> is the full path of your app's EXE, using forward
  slashes ("/") as directory delimeters since the registry would
  interpret backslashes ("\") as keys.  For example, if your app's
  full path is "c:\apps\foo.exe" and you want to disable patching for
  Runtime SmartHeap, you would add the registry key:

  "HKEY_LOCAL_MACHINE\Software\MicroQuill\SmartHeap\Apps\c:/apps/foo.exe"

  At this registry key, add a value entry with value name
  "PatchSystemAllocsOn", of data type REG_DWORD, and value 0 (zero).
  A non-zero value means that SmartHeap should patch Win32 heap APIs; 
  zero means SmartHeap should not patch.



New in SmartHeap 3.1
--------------------

Compiler support
----------------

SmartHeap 3.1 adds support for Microsoft Visual C++ 4.1 and Borland C++ 5.0.


Shared memory support added for Win32
-------------------------------------

The SmartHeap shared memory APIs MemPoolInitNamedShared and
MemPoolAttachShared, already documented in the SmartHeap 3.0
Programmer's Guide, are implemented for Win32 in SmartHeap 3.1.
See "Using shared memory in SmartHeap for Win32" in the Getting
Started and Platform Guide.  See also MemPoolInitNamedSharedEx
in Chapter 4, "Function Reference," of the SmartHeap Programmer's
Guide.


Controlling the small block size threshold
------------------------------------------

A new API, MemPoolSetSmallBlockSize, was added to control the size threshold
at which SmartHeap uses the small-block vs. the general-purpose allocation
algorithm.  The small block threshold was previously fixed at 256 bytes.
See MemPoolSetSmallBlockSize in Chapter 4, "Function Reference," of the
SmartHeap Programmer's Guide.


MEM_POOL_VIRTUAL_LOCK support added for Win32
---------------------------------------------

The MEM_POOL_VIRTUAL_LOCK flag to MemPoolInit is now supported for Win32.
This flag causes memory in the pool to be locked with VirtualLock.  Note
that VirtualLock locks on 30 4K pages, so use MEM_POOL_VIRTUAL_LOCK only
when necessary, and only for very small memory pools.  See MemPoolInit
in Chapter 4, "Function Reference," of the SmartHeap Programmer's
Guide.


NT Service support added to SmartHeap DLL
-----------------------------------------

The SmartHeap DLLs previously stored registry settings under 
HKEY_CURRENT_USER.  As of SmartHeap 3.1, these settings are
stored in HKEY_LOCAL_MACHINE, so that the SmartHeap DLLs can be used
in NT services that run before logon.  See "SmartHeap's automatic DLL 
patching" in the Getting Started and Platform Guide.




New in SmartHeap 3.01
---------------------

SmartHeap 3.01 adds the following features in addition to the
new features described below for SmartHeap 3.0:

SmartHeap 3.01 adds support for the Microsoft Visual C++ 4.0
compiler.  

SmartHeap 3.01 is fully compatible with HeapAgent 2.02, including
the HeapAgent "no-relink" feature.  If you are using both SmartHeap
3.01 and HeapAgent 2.02, you can link with the Runtime SmartHeap
libraries (either static or DLL), and then simply enable HeapAgent
with its auto-load facility or by launching your app from the HeapAgent
user interface.  This means that if your application is compiled with
Microsoft Visual C++ PDB debugging information, there is no need to
recompile or relink your SmartHeap app with the Debug SmartHeap or
HeapAgent libraries -- HeapAgent automatically loads and attaches
to your app whenever you run the app.

SmartHeap 3.01 adds a new pair of APIs for locking a memory pool for
exclusive access.  MemPoolLock gives the current thread exclusive access
to a pool, causing allocation/deallocation calls for the thread to block.
MemPoolUnlock releases the lock.  See "Locking memory pools" in 
"Corrections and additions to the Programmer's Guide," below.

In a few rare cases, you may want to disable SmartHeap patching of
compiler DLLs.  For more information, see "Disabling SmartHeap 
DLL's automatic patching" in "Corrections and additions to the 
Programmer's Guide," below.

Finally, the on-disk sample application have been edited for Win32
compatibility (they were formerly 16-bit Windows samples).  Win32 Microsoft
Visual C++ project files are present for each sample.


New in SmartHeap 3.0
--------------------

SmartHeap 3.0 contains new allocation algorithms that boost
performance 2x or more over SmartHeap 2.x.  Performance is
particularly optimized for small blocks (less than 256 bytes),
since most C and C++ allocations are small.

Also new in SmartHeap 3.0 is automatic patching of MFC and compiler
runtime library (CRT) DLLs at runtime, so you no longer have to use 
rebuilt versions of these compiler DLLs to use SmartHeap with your app.
You must use the DLL version of SmartHeap to take advantage of this
feature (link with shdw32m.lib or shdw32b.lib).

If you want to avoid having SmartHeap patch the MFC and CRT DLLs,
you must statically link with the SmartHeap library shlw32m.lib or
shlw32b.lib. (See also "Disabling SmartHeap DLL's automatic patching"
in "Corrections and additions to the Programmer's Guide," below.)

The fixed-size block size, established with MemPoolSetBlockSizeFS or
MemDefaultPoolBlockSizeFS, now applies only to the MemAllocFS 
SmartHeap API.  The FS block size no longer has any effect on
allocations through malloc, new, or MemAllocPtr.  The reason is that
the new SmartHeap algorithm achieves fixed-size algorithm performance
for all blocks under 256 bytes in size without incurring the memory
waste that would be incurred with a single large FS block size.

SmartHeap 3.0 also adds new debugging functionality, including a
number of new debugging APIs.  Debug SmartHeap 3.0 obtains file names
and line numbers directly from Microsoft Visual C++ PDB debugging
information, so if you're using that compiler, you no longer have
to include a Debug SmartHeap header file or recompile to use Debug
SmartHeap.


1. Installation
---------------

Installation instructions can be found in hardcopy form in the 
in the Getting Started and Platform Guide.

On the program diskette, you will find the following files:

   readme.txt                The ASCII text file you're now reading.
   bin\sh32w32.dll           Runtime SmartHeap dynamic link library.
   bin\sh32w32.dbg           Symbols for Runtime SmartHeap DLL.
   bin\ha300w32.dll          Debug SmartHeap dynamic link library.
   include                   smrtheap.h, shmalloc.h, smrtheap.hpp, 
                               and heapagnt.h.
   msvc\shlw32m.lib          Single-thread static lib for Runtime SmartHeap, 
                               Microsoft Visual C++.
   msvc\shlw32mt.lib         Multi-thread version of above library.
   msvc\shdw32m.lib          Single-thread import lib for Runtime SmartHeap, 
                               Microsoft Visual C++.
   msvc\shdw32mt.lib         Multi-thread version of above.
   msvc\shmfc4m.lib          Static library for Runtime SmartHeap, 
                               statically-linked Runtime MFC 4.0.
   msvc\haw32m.lib           Import library for Debug SmartHeap, 
                               Microsoft Visual C++ 2.x.
   msvc\hamfc32m.lib         Static library for Debug SmartHeap, 
                               statically-linked Debug MFC 3.0 (VC++ 2.x).
   msvc\hamfc4m.lib          Static library for Debug SmartHeap, 
                               statically-linked Debug MFC 4.0 (VC++ 4.x/5.x).
   borland\shlw32b.lib       Single-thread static library for 
                               Runtime SmartHeap, Borland C++ 4.x/5.0.
   borland\shlw32bt.lib      Multi-thread static library for 
                               Runtime SmartHeap, Borland C++ 4.x/5.0.
   borland\shdw32b.lib       Single-thread import library for
                               Runtime SmartHeap, Borland C++ 4.x/5.0.
   borland\shdw32bt.lib      Multi-thread import library for
                               Runtime SmartHeap, Borland C++ 4.x/5.0.
   borland\haw32b.lib        Import library for Debug SmartHeap, 
                               Borland C++ 4.x/5.0.
   other\coff\sh32w32.lib    Runtime SmartHeap DLL import library -- 
                               COFF format
   other\coff\ha300w32.lib   Debug SmartHeap DLL import library -- 
                               COFF format
   other\omf\sh32w32.lib     Runtime SmartHeap DLL import library -- 
                               OMF format
   other\omf\ha300w32.lib    Debug SmartHeap DLL import library -- 
                               OMF format
   source                    Source files for malloc and 
                               operator new interfaces.
   samples                   Sample applications.
   benchmrk                  Sample benchmark program, including
                               source code and documentation.

To install SmartHeap, copy bin\*.* to a directory on your executable PATH.
Next, copy the libraries from one or more of the compiler directories
to a directory on your linker's library file search path.  Finally, copy
include\*.* to a directory on your compiler's include file search path.

You may also copy files from the source and samples sub-directory of the
SmartHeap program diskette to your own working directory in order to 
examine or modify the code contained in these files.

Note that the files on the SmartHeap program diskette are
NOT compressed or copy protected in any way -- simply use the
COPY or XCOPY commands to transfer them to your hard disk.


2. Important information
------------------------

  Size parameter of MemPoolSetSmallBlockSize
  ------------------------------------------

  The maximum value of the size parameter of MemPoolSetSmallBlockSize is
  incorrectly documented in the SmartHeap Programmer's Guide as 1024.  The
  actual maximum value is 1000.


  Specifying processes in which SmartHeap automatically maps shared memory
  ------------------------------------------------------------------------

  MemPoolInitNamedSharedEx causes SmartHeap to immediately map the shared
  memory pool into the address space of each specified process before the
  call to MemPoolInitNamedSharedEx returns.  This is the only way to
  guarantee that the memory pool will be accessible in other processes in
  NT, since the address chosen for the pool may come to be in use in other
  processes between the time the shared pool is created and the time the
  other process(es) call MemPoolAttachShared to map the shared pool into
  their respective address space(s).

  If you have specified a pids array to MemPoolInitNamedSharedEx and you
  are running on NT, then you may specify the pool parameter with a NULL
  name parameter to MemPoolAttachShared when calling this function from
  one of the processes you previously specified to MemPoolInitNamedSharedEx.
  This is the only case where the name parameter of MemPoolAttachShared is
  optional in the Win32 SmartHeap implementation.  You may also specify both
  name and pool parameters, or just the name parameter if you wish.  For
  Win95 compatibility, the name parameter must always be specified.



  Default pool floor value changed to 256K
  ----------------------------------------

  In SmartHeap 3.0, the default floor value for memory pools was zero,
  meaning that if all allocations in a pool are freed, all the memory
  in the pool is returned to the operating system.  In SmartHeap 3.1,
  the default floor value has changed to 256K, meaning that, by default,
  memory pools will always retain at least 256K of memory for future
  allocations.

  This change in the default floor is a performance optimization to
  reduce the number of operating system allocation/deallocation requests.
  You can change a pool's floor value with MemPoolSetFloor.



  Disabling SmartHeap DLL's automatic patching
  --------------------------------------------

  When you link with the DLL version of SmartHeap, SmartHeap automatically
  patches heap routines in compiler DLLs, such as the CRT and MFC DLLs.
  This patching is required if you are using MFC, OWL, or other DLLs that
  share heap memory with their client EXE.

  Note: this procedure is unnecessary if you statically link SmartHeap
  rather than use the SmartHeap DLL.  Only the SmartHeap DLL does any
  patching of other DLLs.

  If you are not using MFC or OWL (or similar) DLLs, you can disable
  SmartHeap's patching of compiler DLLs by adding the following key and
  value to the NT or Windows 95 registry:

  for Runtime SmartHeap, add the registry key:
  "HKEY_LOCAL_MACHINE\Software\MicroQuill\SmartHeap\Apps\<app-name>"

  for Debug SmartHeap, add the registry key:
  "HKEY_LOCAL_MACHINE\Software\MicroQuill\HeapAgent\Apps\<app-name>"

  where <app-name> is the full path of your app's EXE, using forward
  slashes ("/") as directory delimeters since the registry would
  interpret backslashes ("\") as keys.  For example, if your app's
  full path is "c:\apps\foo.exe" and you want to disable patching for
  Runtime SmartHeap, you would add the registry key:

  "HKEY_LOCAL_MACHINE\Software\MicroQuill\SmartHeap\Apps\c:/apps/foo.exe"

  At this registry key, add the value name "PatchProcessOn" of data type
  REG_DWORD, and value 0 (zero).  A non-zero value means that SmartHeap
  should patch DLLs; zero means SmartHeap should not patch.

  You can also disable patching of Win32 APIs.  To disable Win32 API
  patching, at the same registry key, add the value name "PatchSystemAllocsOn" 
  of data type REG_DWORD, and value 0 (zero).  A non-zero value means that
  SmartHeap should patch Win32 APIs; zero means SmartHeap should not patch.

  If you want to disable patching in certain DLLs in your application,
  but not in the entire process, you can do this by adding a registry
  key:

  for Runtime SmartHeap, add the registry key:
  "HKEY_LOCAL_MACHINE\Software\MicroQuill\SmartHeap\Apps\<app-name>\SkipDLLs"

  for Debug SmartHeap, add the registry key:
  "HKEY_LOCAL_MACHINE\Software\MicroQuill\HeapAgent\Apps\<app-name>\SkipDLLs"

  At this registry key, add DLLs that you do *not* want SmartHeap to patch,
  as follows:

  For each DLL you want SmartHeap to skip (i.e. not patch), add the value
  name "File<n>" of data type REG_SZ and value equal to the DLL name
  (not the full path of the DLL -- just name and extension), where <n>
  is 0 (zero) for the first DLL you add, 1 (one) for the second, and so
  on.

  Add the value name "FileCount" of data type REG_DWORD and value equal to
  the number of DLLs you have added.

  For example, if you want to skip DLLs foo.dll and bar.dll, you would add
  the following three registry values:
 
  - Name "File0", type REG_SZ, value "foo.dll"
  - Name "File1", type REG_SZ, value "bar.dll"
  - Name "FileCount", type REG_DWORD, value 2

  You can use the Win32 registry API to programmatically add these
  registry keys and values.  You should do so from your app's setup
  program if your application uses the Runtime SmartHeap DLL and you
  do not want SmartHeap to patch one or more DLLs used by your application.
  

  
  MFC 3.0/4.0 support
  -------------------

  Runtime SmartHeap supports only Release MFC (not Debug MFC).
  Debug SmartHeap supports both Release and Debug MFC.

  For the MFC DLL, the SmartHeap DLL automatically patches the MFC DLL at
  runtime so that both MFC and your application use SmartHeap.  Because of 
  this, you no longer need rebuilt MFC/CRT DLLs for Runtime or Debug 
  SmartHeap -- just link with shdw32m.lib or shdw32b.lib.

  To use Runtime SmartHeap with statically linked Release MFC 4.0,
  you must link shmfc4m.lib; place this library before shlw32m.lib
  or shdw32m.lib on the linker command line.

  To use Debug SmartHeap with statically linked Debug MFC 4.0, you must link
  hamfc4m.lib; place this library before haw32m.lib on the linker
  command line.

  To use Debug SmartHeap with statically linked Debug MFC 3.0, you must link
  hamfc32m.lib; place this library before haw32m.lib on the linker
  command line.


  Win32s support
  --------------

  Only the statically linked SmartHeap 3.0 libraries support Win32s.
  Link with shlw32m.lib or shlw32b.lib for Win32s compatibility.
  Debug SmartHeap is available only in DLL form, so it does not support
  Win32s -- debug Win32s applications under Windows NT or Windows 95.
  

  Multi-threaded applications
  ---------------------------

  This release supports multi-threaded Windows NT applications.  It includes
  a thread-reentrant DLL and static libraries for Microsoft C/C++.

  Runtime SmartHeap DOES NOT serialize requests by default.  Therefore, if 
  you link SmartHeap with an application that uses multiple threads, you 
  must define the following global variable at file scope in your application:

     unsigned MemDefaultPoolFlags = MEM_POOL_SERIALIZE;

  Defining the above variable is necessary even if you call only malloc
  or operator new from one thread, because the C runtime library may have 
  calls to malloc from multiple threads and expect them to be automatically
  serialized.

  SmartHeap avoids serialization overhead completely by default, so 
  allocations, frees, and other operations involving the pool incur no
  thread-synchronization overhead.  If you use a pool in more than one
  thread, then supply MEM_POOL_SERIALIZE when creating that pool.
 
  Since each SmartHeap memory pool is a completely isolated data structure, 
  you can minimize heap contention and maximize concurrence by allocating 
  data referenced in only one thread (at a time) in separate non-serialized
  memory pools.


  Using SmartHeap with Win32s
  ---------------------------

  The DLL version of SmartHeap 3.0 does not support Win32s.  You can
  use the statically linkable SmartHeap library (shlw32m.lib or shlw32b.lib)
  for Win32s applications.


  Locking memory pools
  --------------------

  If you use MemPoolWalk to enumerate the blocks in a memory pool in a
  multi-threaded application, you should first lock the pool using
  MemPoolLock.  This prevents other threads from allocating or freeing
  from the pool while it is locked.  When you finish enumerating the pool,
  unlock the pool with MemPoolUnlock.

  Important!  MemPoolLock has no effect unless MEM_POOL_SERIALIZE was
  supplied at the time the pool was created.
  

  Non-local exit (longjmp) from SmartHeap error handler
  -----------------------------------------------------

  This release adds a new SmartHeap API, MemErrorUnwind, that must be
  called before a non-local exit (e.g. longjmp) from a custom error
  handler you establish with MemSetErrorHandler.  SmartHeap detects
  per-thread recursive re-entry into the error handler (due to calling
  SmartHeap functions from a user error handler that themselves result
  in error(s)).  Failure to call MemErrorUnwind before longjmp'ing out
  of an error handler can result in SmartHeap reporting recursive
  re-entry to an error handler where there is none.

     void MemErrorUnwind(void);


  Using MEM_ZEROINIT with MemReAllocPtr or MemReAlloc
  ---------------------------------------------------

  MEM_ZEROINIT guarantees to zero-initialize expanded
  bytes _only_ if MEM_ZEROINIT was supplied with the original
  allocation, and if MEM_ZEROINIT is supplied with _all_ previous
  reallocations, _and_ if no previous reallocation reduced the
  size of the block.

  This is because SmartHeap stores only the actual block size,
  not the requested block size.  For example, suppose you allocate 
  a 12-byte block and place non-zero values in the last two bytes. 
  Then you reallocate the block to 10 bytes but the actual block size
  remains at 12 bytes.  Then you reallocate the block to 16 bytes.
  SmartHeap zero-initializes only bytes 13 through 16 (not 11 and 12),
  because the block size is actually expanding from 12 to 16.

  You can use MemSizePtr or MemSize to determine the actual block
  size and thus be sure of which bytes MEM_ZEROINIT clears on calls
  to MemReAllocPtr or MemReAlloc.


  Changing fixed-size block size, or debug guards for malloc or new
  -----------------------------------------------------------------

  The functions MemSetBlockSizeFS, dbgMemSetGuardSize, etc. change
  the properties of a memory pool, but they cannot be called once
  memory has been allocated.  Since malloc is often called by the C
  runtime startup code before your application gets control, SmartHeap
  supplies global variables that you can use to initialize the properties
  of the default pool at link time.

  The variables are MemDefaultPoolPageSize, MemDefaultPoolBlockSizeFS,
  dbgMemGuardSize, dbgMemGuardFill, dbgMemFreeFill, and
  dbgMemInUseFill.  See these names in the function reference of the
  Programmer's Guide for details.




3. Sample programs
------------------

Several sample applications are included with this release to show
you how to use SmartHeap.  The source code for each application is
present in a separate sub-directory of the SAMPLES directory.
The most complete example is a DLL for managing linked lists, and
a corresponding application that calls the linked list manager.
Both C and C++ versions of this application are provided.
For more detailed information on the contents of the examples, see
the INDEX.TXT file in the SAMPLES directory.

The make files included with the on-disk samples are Microsoft Visual C++
project files.  Most of the samples include only one or two source
files, so you can easily create your own project or make file if you
are using a different compiler.

Note that samples\sharemem contains samples illustrating the SmartHeap 
shared memory APIs.

Numerous additional examples are present in the SmartHeap Programmer's
Guide.  Each function description in Chapter 4, Reference,
includes a complete example.


4. Evaluating SmartHeap performance
-----------------------------------

By popular demand, we have added a benchmrk directory with SmartHeap.
It contains contains an overview file (perfeval.txt), the source code
for a benchmark testing program (shbench.c) and an accompanying 
shbench.txt file.  These files contain useful information about
evaluating SmartHeap performance and producing memory management 
benchmark tests.


5. Technical support
--------------------

Before calling technical support about a SmartHeap problem, please
read Appendix B of the SmartHeap Programmer's Guide, which lists common
questions and answers as well as troubleshooting suggestions.

You can contact MicroQuill technical support at:

   Address     MicroQuill Software Publishing, Inc.
               10500 Valley View Rd., Bothell, WA 98011

   Phone       206-402-9400
   Fax         206-481-4442

   Internet    support@microquill.com
   CIS         74777,3307
                or
               GO MICROQUILL

Our technical support staff is available between 8 a.m. and 5 p.m., 
Pacific time, Monday through Friday.
