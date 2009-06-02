exwise v0.5
(c) 1998 Andrew de Quincey
http://www.tardis.ed.ac.uk/~adq
adq@tardis.ed.ac.uk


----------------------------------
Info:

This decompresses WISE install executables
(See http://www.wisesolutions.com/ for more details)

----------------------------------
Usage:

Type exwise <wise executable file.exe>

The contents will be extracted into the current directory. 
Note that filenames are NOT preserved in the wise executable; you need
to parse the install script to find those out.... this I have
not yet got round to doing.

The scriptfile will be called "script.bin" to make it easier to find...

----------------------------------
Notes:

Most of this source is from Info-Zip v5.31 (see file src/Copying)

Only the file exwise.c is actually written by me.

The WISE executable is basically a stub with a load of Zip deflated files
stuck on the end, missing the standard zip headers.

----------------------------------
Problems:

Filenames.

----------------------------------
Bugs:

None that I know of, but I'm sure they're there. If you find one, please tell
me about it!


----------------------------------
Legal:

* Permission is granted to any individual or institution to use, copy, or 
  redistribute this software so long as all of the original files are 
  included unmodified, that it is not sold for profit, and that this copyright
  notice is retained.

* If you wish to use any code from this package in another product,
  or wish to sell it as a standalone product, you *must* contact me.

* Feel free to develop the code, but remember that you are not allowed to
  distribute the modified copies. Send me a copy of your additions, and
  I shall include them in the next version (indicating which parts of
  the code are whose, naturally).

* This software is provided "as is". The author annot be held responsible
  for any loss of data, or other misfortunes resulting from the use of this
  program.

* Likewise, the author cannot be held responsible for the use, or misuse of
  this software.
