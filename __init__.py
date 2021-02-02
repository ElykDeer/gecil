import binaryninja as bn
from gecil.gecil import gecil
from gecil import hlil

def do_the_thing(bv, bn_func):
  text_box = bn.interaction.MultilineTextField("void foo() { ...")
  bn.interaction.get_form_input([text_box], "Input Function Source")

  good_enough_hlil_func, imaginary_memory_space = gecil(text_box.result)

  hlil_func = bn_func.hlil

  match = True
  instruction_generator = hlil_func.instructions
  for geil in good_enough_hlil_func.instructions:
    if geil.operation is hlil.HighLevelILOperation.HLIL_COMMENT:
      continue

    bnil = next(instruction_generator)

    if bnil.operation.name != geil.operation.name:
      match = False

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

  instruction_generator = hlil_func.instructions
  for geil in good_enough_hlil_func.instructions:
    if geil.operation is not hlil.HighLevelILOperation.HLIL_COMMENT:
      continue

    bnil = next(instruction_generator)

    bn_func.set_comment_at(bnil.address, geil.value)

bn.PluginCommand.register_for_function("Annotate Binary From Source", "Annotate binary from source", do_the_thing)
