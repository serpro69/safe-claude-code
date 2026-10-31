# Working files

- Keep working files inside this project. When you extract text from PDFs or
  other sources, save it under `sources/text/` (create the folder if needed),
  one `.txt` file per source, named after the source file. Reuse those files in
  later sessions instead of extracting again.
- Do not use your temporary scratchpad folder for files you will search or
  read again. Each session gets a new scratchpad, and commands that work
  there can need approval.
- Do not `cd` to another folder before running a command. Run commands from
  the project folder and refer to files by their path relative to it, for
  example `grep -n "word problem" "sources/text/Fuchs 2015.txt"`.
- To search extracted text, prefer the built-in Grep and Read tools over long
  shell pipelines.
