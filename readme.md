# gecil - the good enough c-to-il "compiler"

We take this binary:

![hey stop hovering here](images/original.png?raw=true "Original HLIL")

and this source snippet:

![no i really mean it](images/source.png?raw=true "Source code snippet")

to make this:

![:(](images/annotated.png?raw=true "Annotated HLIL")

---

This serves just as a minimal proof of concept that one may be able to compile limited snippets of code, such as a single function, to BinaryNinja's HLIL for the purposes of matching it against HLIL generated from a compiled binary and propagating information from the source to the BNDB.

This example is only complete enough to compile hello world, and to copy comments from source to the BNDB.

Graph matching is also only complete enough to do basically just an exact match.

It's just a POC.

---

To run this:

 1. Have BinaryNinja installed (plus the headless API)
 2. `./test_matching_algo.py`
 3. Open `output.bndb` in BinaryNinja and look at the main function
 4. Say "oohh" and "aahh"

---

File list:

 - gecil.py - This is the compiler
 - gecil.lark - This is the EBNF/Lark grammar I'm using to parse C
 - test_matching_algo.py - Is the exemplary graph-matching/artifact propagation "engine"
 - hlil.py - Is a bunch of garbage you should ignore; HLIL in the BN API doesn't have the required APIs to "create" arbitrary instructions, so copy/pasted/fixed that up
 - example.c - The file used for the test matching algo
 - example - compiled with `gcc example.c -o example`
 - requirements.txt - you need to have `lark-parser` installed to run this demo/POC

---


