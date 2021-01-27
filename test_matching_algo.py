#!/usr/bin/env python3

from gecil import gecil
import hlil
import binaryninja as bn

# Given some source for a function
main_function_source = """
int main()
{
  // printf takes a format string and prints it to standard out
  printf("Hello world!");

  // return 0 means that we ran correctly and have no errors
  return 0;
}
"""

# can we compile it to HLIL? (gecil = "good enough c to il")
good_enough_hlil_func, imaginary_memory_space = gecil(main_function_source)

# And, with a possible location for that function in the binary,
possible_binary_location = 0x401149
bv = bn.open_view("example")
bv.update_analysis_and_wait()
bn_func = bv.get_function_at(possible_binary_location)
hlil_func = bn_func.hlil

# can we match the graphs,
#  (here I'm demonstrating matching on basically an exact match,
#   because graph theory is hard, but also string arguments!)
match = True
instruction_generator = hlil_func.instructions
for geil in good_enough_hlil_func.instructions:
  if geil.operation is hlil.HighLevelILOperation.HLIL_COMMENT:
    continue

  bnil = next(instruction_generator)

  # The exact match bit
  if bnil.operation.name != geil.operation.name:
    match = False

  # String argument matching
  if geil.operation is hlil.HighLevelILOperation.HLIL_CALL:
    string_start_address = geil.operands[1].value
    string_end_address = string_start_address
    while imaginary_memory_space[string_end_address] != "\x00":
      string_end_address += 1
    source_string = imaginary_memory_space[string_start_address:string_end_address]
    print(f"Found string from source: {source_string}")

    binary_string = '"' + str(bv.get_string_at(bnil.operands[1][0].constant)) + '"'
    print(f"Found string from binary: {binary_string}")

    if source_string != binary_string:
      match = False

print(f"Match: {match}")

# and propagate artifacts from the source to the BNDB?
instruction_generator = hlil_func.instructions
for geil in good_enough_hlil_func.instructions:
  if geil.operation is not hlil.HighLevelILOperation.HLIL_COMMENT:
    continue

  bnil = next(instruction_generator)

  bn_func.set_comment_at(bnil.address, geil.value)

# And save the BNDB so you can view my work
print("Saving BNDB...")
bv.create_database("output.bndb")
print("done.")

# my binja crashes on close, which may just be the result of my dev work atm
print("\n\n\n\n")