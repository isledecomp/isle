// Sample for python unit tests
// Not part of the decomp

// While it's reasonable to expect a well-formed file (and clang-format
// will make sure we get one), this will put the parser through its paces.

// FUNCTION: TEST 0x1234
void curly_with_spaces()
  {
  static char* msg = "hello";
  }

// FUNCTION: TEST 0x5555
void weird_closing_curly()
{
  int x = 123; }

// FUNCTION: HELLO 0x5656
void bad_indenting() {
  if (0)
{
  int y = 5;
}}
