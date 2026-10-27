# exe-explain

Reads a Windows PE file (exe or dll) without running it and writes a report in which every statement is a numbered claim that points at the evidence it came from: an import, a string and its file offset, a section and its entropy, a header field. Each claim has a certainty label, and the report ends with a list of things that could not be determined.

No dependencies; needs Node 22 or newer. The PE parser is written from scratch.

## Usage

    node bin/exe-explain.js app.exe                  # Markdown to stdout
    node bin/exe-explain.js app.exe --format html -o report.html
    node bin/exe-explain.js app.exe --format json

Claims come from a fixed set of rules (src/rules.js), for example importing WinInet functions gives "may make HTTP requests". The wording is deliberately hedged and the tool never labels a file malicious or safe. Certainty is `observed` (read straight from the file), `moderate` (a rule matched two or more pieces of evidence) or `low` (one piece).

### Optional Ollama summary

    node bin/exe-explain.js app.exe --ollama llama3 [--ollama-url http://127.0.0.1:11434]

The collected evidence is sent to Ollama's `/api/generate` and the reply is parsed as JSON claims. Any claim that cites no evidence ID, cites an ID that does not exist, or uses verdict words like "malicious" is dropped and counted in the report. Surviving claims are labelled `model`. If the request fails the report is still produced, with a note under unknowns. This adapter is only tested against a fake HTTP server in the test suite; I have not run it against a real model.

## Tests

    node --test "test/*.test.js"

The tests build small synthetic PE32 and PE32+ files in memory (test/helpers/build-pe.js), and also truncate and randomly corrupt them to check the parser fails cleanly.

## Limits

- No disassembly. Claims are about imports, strings and structure, not code behavior.
- Delay-load and bound imports are not parsed (delay-loaded DLLs appear only as a plain import from the delay-load stub DLL), so some capabilities will be missed.
- Resources are listed by type and ID only; version info and manifests are not decoded.
- Signatures are not verified. .NET metadata is not read.
- Strings are ASCII and UTF-16LE with length 5 or more; the rule patterns are simple regexes and will have false positives, such as version numbers matching the IPv4 pattern.
- Packed files will produce few claims; high entropy is reported but nothing is unpacked.
- The Ollama prompt only lists the evidence behind rule claims, so the model sees a limited view. Validation checks that IDs exist, not that the sentence is a faithful reading of them.
