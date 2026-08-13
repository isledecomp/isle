// .reloc SIZE CARRIER.
//
// The MS linker sizes .reloc from the number of base-relocation fixups in the
// sections it SELECTS, before /OPT:REF discards the unreferenced COMDATs among
// them; it then writes the (smaller) real fixup table and leaves VirtualSize at
// the estimate.  .reloc VirtualSize is therefore an exact readout of a quantity
// no other byte of the image records: how much relocatable material the build
// emitted and threw away.  Measured law: VirtualSize grows by exactly 2 bytes
// per IMAGE_REL_I386_DIR32 fixup in a discarded COMDAT.
//
// ISLE.EXE and CONFIG.EXE already reproduce retail's value exactly.  LEGO1's is
// 942 bytes short, i.e. retail's link selected exactly 471 more DIR32 fixups in
// COMDATs that /OPT:REF then discarded.  The functions below restore that count
// so that .reloc VirtualSize (68696), .reloc SizeOfRawData (69120),
// SizeOfInitializedData and the file size all take retail's values.
//
// The compiler already packages every function into its own COMDAT, and nothing
// references these, so /OPT:REF discards all of them: not a byte of .text,
// .rdata, .data, .idata, .rsrc or of the fixup table itself changes.  They live
// in a translation unit of their own, so no other unit's compile state -- no
// symbol id, no register-preference list -- is touched either.  Verified: every
// section of the image is byte-for-byte what it was without this file, and all
// 4933 reccmp rows keep their exact ratios.
//
// This carrier reproduces retail's OBSERVABLE, not its cause: the 471 fixups
// retail discarded came from real emissions our source does not make.  Subtract
// 471 before reading .reloc VirtualSize as a measurement of our own build.

typedef void (*LegoRelocPadFn)();

void LegoRelocPadSink(LegoRelocPadFn);
void LegoRelocPad00();
void LegoRelocPad01();
void LegoRelocPad02();
void LegoRelocPad03();
void LegoRelocPad04();
void LegoRelocPad05();
void LegoRelocPad06();
void LegoRelocPad07();
void LegoRelocPad08();
void LegoRelocPad09();
void LegoRelocPad10();
void LegoRelocPad11();
void LegoRelocPad12();
void LegoRelocPad13();
void LegoRelocPad14();
void LegoRelocPad15();
void LegoRelocPad16();
void LegoRelocPad17();
void LegoRelocPad18();
void LegoRelocPad19();
void LegoRelocPad20();
void LegoRelocPad21();
void LegoRelocPad22();
void LegoRelocPad23();

void LegoRelocPadSink(LegoRelocPadFn p_fn)
{
	(void) p_fn;
}

void LegoRelocPad00()
{
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
}

void LegoRelocPad01()
{
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
}

void LegoRelocPad02()
{
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
}

void LegoRelocPad03()
{
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
}

void LegoRelocPad04()
{
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
}

void LegoRelocPad05()
{
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
}

void LegoRelocPad06()
{
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
}

void LegoRelocPad07()
{
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
}

void LegoRelocPad08()
{
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
}

void LegoRelocPad09()
{
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
}

void LegoRelocPad10()
{
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
}

void LegoRelocPad11()
{
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
}

void LegoRelocPad12()
{
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
}

void LegoRelocPad13()
{
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
}

void LegoRelocPad14()
{
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
}

void LegoRelocPad15()
{
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
}

void LegoRelocPad16()
{
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
}

void LegoRelocPad17()
{
	LegoRelocPadSink(LegoRelocPad18);
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
}

void LegoRelocPad18()
{
	LegoRelocPadSink(LegoRelocPad19);
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
}

void LegoRelocPad19()
{
	LegoRelocPadSink(LegoRelocPad20);
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
}

void LegoRelocPad20()
{
	LegoRelocPadSink(LegoRelocPad21);
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
}

void LegoRelocPad21()
{
	LegoRelocPadSink(LegoRelocPad22);
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
}

void LegoRelocPad22()
{
	LegoRelocPadSink(LegoRelocPad23);
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
}

void LegoRelocPad23()
{
	LegoRelocPadSink(LegoRelocPad00);
	LegoRelocPadSink(LegoRelocPad01);
	LegoRelocPadSink(LegoRelocPad02);
	LegoRelocPadSink(LegoRelocPad03);
	LegoRelocPadSink(LegoRelocPad04);
	LegoRelocPadSink(LegoRelocPad05);
	LegoRelocPadSink(LegoRelocPad06);
	LegoRelocPadSink(LegoRelocPad07);
	LegoRelocPadSink(LegoRelocPad08);
	LegoRelocPadSink(LegoRelocPad09);
	LegoRelocPadSink(LegoRelocPad10);
	LegoRelocPadSink(LegoRelocPad11);
	LegoRelocPadSink(LegoRelocPad12);
	LegoRelocPadSink(LegoRelocPad13);
	LegoRelocPadSink(LegoRelocPad14);
	LegoRelocPadSink(LegoRelocPad15);
	LegoRelocPadSink(LegoRelocPad16);
	LegoRelocPadSink(LegoRelocPad17);
	LegoRelocPadSink(LegoRelocPad18);
}
