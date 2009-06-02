/* exwise v1.0
   (c) 1998 Andrew de Quincey
   
   portions based on funzip.c by M. Adler et al. (see below)
   portions based on Info-ZIP v5.31 (see file "Copying")
*/

#ifndef VERSION
#define VERSION "v1.0"
#endif

/* original funzip.c header */
/* You can do whatever you like with this source file, though I would
   prefer that if you modify it and redistribute it that you include
   comments to that effect with your name and the date.  Thank you.

   History:
   vers     date          who           what
   ----   ---------  --------------  ------------------------------------
   1.0    13 Aug 92  M. Adler        really simple unzip filter.
   1.1    13 Aug 92  M. Adler        cleaned up somewhat, give help if
                                     stdin not redirected, warn if more
                                     zip file entries after the first.
   1.2    15 Aug 92  M. Adler        added check of lengths for stored
                                     entries, added more help.
   1.3    16 Aug 92  M. Adler        removed redundant #define's, added
                                     decryption.
   1.4    27 Aug 92  G. Roelofs      added exit(0).
   1.5     1 Sep 92  K. U. Rommel    changed read/write modes for OS/2.
   1.6     6 Sep 92  G. Roelofs      modified to use dummy crypt.c and
                                     crypt.h instead of -DCRYPT.
   1.7    23 Sep 92  G. Roelofs      changed to use DOS_OS2; included
                                     crypt.c under MS-DOS.
   1.8     9 Oct 92  M. Adler        improved inflation error msgs.
   1.9    17 Oct 92  G. Roelofs      changed ULONG/UWORD/byte to ulg/ush/uch;
                                     renamed inflate_entry() to inflate();
                                     adapted to use new, in-place zdecode.
   2.0    22 Oct 92  M. Adler        allow filename argument, prompt for
                                     passwords and don't echo, still allow
                                     command-line password entry, but as an
                                     option.
   2.1    23 Oct 92  J-l. Gailly     fixed crypt/store bug,
                     G. Roelofs      removed crypt.c under MS-DOS, fixed
                                     decryption check to compare single byte.
   2.2    28 Oct 92  G. Roelofs      removed declaration of key.
   2.3    14 Dec 92  M. Adler        replaced fseek (fails on stdin for SCO
                                     Unix V.3.2.4).  added quietflg for
                                     inflate.c.
   3.0    11 May 93  M. Adler        added gzip support
   3.1     9 Jul 93  K. U. Rommel    fixed OS/2 pipe bug (PIPE_ERROR)
   3.2     4 Sep 93  G. Roelofs      moved crc_32_tab[] to tables.h; used FOPx
                                     from unzip.h; nuked OUTB macro and outbuf;
                                     replaced flush(); inlined FlushOutput();
                                     renamed decrypt to encrypted
   3.3    29 Sep 93  G. Roelofs      replaced ReadByte() with NEXTBYTE macro;
                                     revised (restored?) flush(); added FUNZIP
   3.4    21 Oct 93  G. Roelofs      renamed quietflg to qflag; changed outcnt,
                     H. Gessau       second updcrc() arg and flush() arg to ulg;
                                     added inflate_free(); added "g =" to null
                                     getc(in) to avoid compiler warnings
   3.5    31 Oct 93  H. Gessau       changed DOS_OS2 to DOS_NT_OS2
   3.6     6 Dec 93  H. Gessau       added "near" to mask_bits[]
   3.7     9 Dec 93  G. Roelofs      added extent typecasts to fwrite() checks
   3.8    28 Jan 94  GRR/JlG         initialized g variable in main() for gcc
   3.81   22 Feb 94  M. Hanning-Lee  corrected usage message
   3.82   27 Feb 94  G. Roelofs      added some typecasts to avoid warnings
   3.83   22 Jul 94  G. Roelofs      changed fprintf to macro for DLLs
    -      2 Aug 94  -               public release with UnZip 5.11
    -     28 Aug 94  -               public release with UnZip 5.12
   3.84    1 Oct 94  K. U. Rommel    changes for Metaware High C
   3.85   29 Oct 94  G. Roelofs      changed fprintf macro to Info
   3.86    7 May 95  K. Davis        RISCOS patches;
                     P. Kienitz      Amiga patches
   3.87   12 Aug 95  G. Roelofs      inflate_free(), DESTROYGLOBALS fixes
   3.88    4 Sep 95  C. Spieler      reordered macro to work around MSC 5.1 bug
   3.89   22 Nov 95  PK/CS           ifdef'd out updcrc() for ASM_CRC
   3.9    17 Dec 95  G. Roelofs      modified for USE_ZLIB (new fillinbuf())
    -     30 Apr 96  -               public release with UnZip 5.2
   3.91   17 Aug 96  G. Roelofs      main() -> return int (Peter Seebach)
   3.92   13 Apr 97  G. Roelofs      minor cosmetic fixes to messages
    -     22 Apr 97  -               public release with UnZip 5.3
    -     31 May 97  -               public release with UnZip 5.31
 */


#ifndef FUNZIP
#define FUNZIP //make sure FUNZIP is defined afterwards
#endif
#define UNZIP_INTERNAL
#include "unzip.h"
#include "crypt.h"
#include "ttyio.h"

#ifdef EBCDIC
#  undef EBCDIC                 /* don't need ebcdic[] */
#endif
#include "tables.h"             /* crc_32_tab[] */

#ifndef USE_ZLIB  /* zlib's function is called inflate(), too */
#  define UZinflate inflate
#endif

/* PKZIP header definitions */
#define ZIPMAG 0x4b50           /* two-byte zip lead-in */
#define LOCREM 0x0403           /* remaining two bytes in zip signature */
#define LOCSIG 0x04034b50L      /* full signature */
#define LOCFLG 4                /* offset of bit flag */
#define  CRPFLG 1               /*  bit for encrypted entry */
#define  EXTFLG 8               /*  bit for extended local header */
#define LOCHOW 6                /* offset of compression method */
#define LOCTIM 8                /* file mod time (for decryption) */
#define LOCCRC 12               /* offset of crc */
#define LOCSIZ 16               /* offset of compressed size */
#define LOCLEN 20               /* offset of uncompressed length */
#define LOCFIL 24               /* offset of file name field length */
#define LOCEXT 26               /* offset of extra field length */
#define LOCHDR 28               /* size of local header, including LOCREM */
#define EXTHDR 16               /* size of extended local header, inc sig */

/* GZIP header definitions */
#define GZPMAG 0x8b1f           /* two-byte gzip lead-in */
#define GZPHOW 0                /* offset of method number */
#define GZPFLG 1                /* offset of gzip flags */
#define  GZPMUL 2               /* bit for multiple-part gzip file */
#define  GZPISX 4               /* bit for extra field present */
#define  GZPISF 8               /* bit for filename present */
#define  GZPISC 16              /* bit for comment present */
#define  GZPISE 32              /* bit for encryption */
#define GZPTIM 2                /* offset of Unix file modification time */
#define GZPEXF 6                /* offset of extra flags */
#define GZPCOS 7                /* offset of operating system compressed on */
#define GZPHDR 8                /* length of minimal gzip header */

/* Macros for getting two-byte and four-byte header values */
#define SH(p) ((ush)(uch)((p)[0]) | ((ush)(uch)((p)[1]) << 8))
#define LG(p) ((ulg)(SH(p)) | ((ulg)(SH((p)+2)) << 16))

/* Function prototypes */
void err OF((int, char *));
void extract(void);
int main OF((int, char **));


/* Globals */
FILE *out;                      /* output file (*in moved to G struct) */
ulg outsiz;                     /* total bytes written to out */

/* Masks for inflate.c */
ZCONST ush near mask_bits[] = {
    0x0000,
    0x0001, 0x0003, 0x0007, 0x000f, 0x001f, 0x003f, 0x007f, 0x00ff,
    0x01ff, 0x03ff, 0x07ff, 0x0fff, 0x1fff, 0x3fff, 0x7fff, 0xffff
};

#ifdef USE_ZLIB

int fillinbuf(__G)
__GDEF
/* Fill input buffer for pull-model inflate() in zlib.  Return the number of
 * bytes in inbuf. */
{
/*   GRR: check return value from fread(): same as read()?  check errno? */
  if ((G.incnt = fread((char *)G.inbuf, 1, INBUFSIZ, G.in)) <= 0)
    return 0;
  G.inptr = G.inbuf;

  return G.incnt;

}

#endif /* USE_ZLIB */



#if (!defined(USE_ZLIB) || defined(USE_OWN_CRCTAB))
#ifdef USE_ZLIB
uLongf *get_crc_table()
{
  return (uLongf *)crc_32_tab;
}
#else /* !USE_ZLIB */
ulg near *get_crc_table()
{
  return crc_32_tab;
}
#endif /* ?USE_ZLIB */
#endif /* !USE_ZLIB || USE_OWN_CRCTAB */


void err(n, m)
int n;
char *m;
/* Exit on error with a message and a code */
{
  Info(slide, 1, ((char *)slide, "\nexwise error: %s\n", m));
  DESTROYGLOBALS()
  EXIT(n);
}


int flush(w)    /* used by inflate.c (FLUSH macro) */
ulg w;          /* number of bytes to flush */
{
  G.crc32val = crc32(G.crc32val, slide, (extent)w);
  if (fwrite((char *)slide,1,(extent)w,out) != (extent)w && !PIPE_ERROR)
    err(9, "out of space on stdout");
  outsiz += w;
  return 0;
}

// table for checking the version of the STUB file
static int checkTable[][2] = {{0x3114, 0x3780},
			      {0x3150, 0x37d0},
			      {0x2988, 0x3000},
			      {-1, -1}};
enum exe_type
{
	NE,
	PE
};

typedef int bool;

struct wise_format
{
	enum exe_type type; //NE | PE
	size_t exec_length; //length of executable part
	bool has_dll_name; 
	size_t header_size;
	int archive_size_offset; //offset of archive size field | -1
	bool has_text_strings;
	int filename_offset;     //offset of filename in archive information file | -1
	size_t exe_code_size;
	size_t exe_data_size;
	bool crc_present;
};

static struct wise_format wise_formats[] =
{
//NE
	{NE, 0x84b0, FALSE, 0x11, -1,   FALSE, 0x04, 0,      0,      FALSE},
	{NE, 0x3e10, FALSE, 0x1e, -1,   FALSE, 0x04, 0,      0,      TRUE },
	{NE, 0x3e50, FALSE, 0x1e, -1,   FALSE, 0x04, 0,      0,      TRUE },
	{NE, 0x3c20, FALSE, 0x1e, -1,   FALSE, 0x04, 0,      0,      TRUE },
	{NE, 0x3c30, FALSE, 0x22, -1,   FALSE, 0x04, 0,      0,      TRUE },
	{NE, 0x3660, FALSE, 0x40, 0x3c, FALSE, 0x04, 0,      0,      TRUE },
	{NE, 0x36f0, FALSE, 0x48, 0x44, FALSE, 0x1c, 0,      0,      TRUE }, 
	{NE, 0x3770, FALSE, 0x50, 0x4c, FALSE, 0x1c, 0,      0,      TRUE },
	{NE, 0x3780, TRUE,  0x50, 0x4c, FALSE, 0x1c, 0,      0,      TRUE },
	{NE, 0x37b0, TRUE,  0x50, 0x4c, FALSE, 0x1c, 0,      0,      TRUE },
	{NE, 0x37d0, TRUE,  0x50, 0x4c, FALSE, 0x1c, 0,      0,      TRUE },
	{NE, 0x3c80, TRUE,  0x5a, 0x4c, TRUE,  0x1c, 0,      0,      TRUE },
	{NE, 0x3bd0, TRUE,  0x5a, 0x4c, TRUE,  0x1c, 0,      0,      TRUE },
	{NE, 0x3c10, TRUE,  0x5a, 0x4c, TRUE,  0x1c, 0,      0,      TRUE },
//PE
	{PE, 0x6e00, FALSE, 0x50, 0x4c, FALSE, 0x1c, 0x3cf4, 0x1528, TRUE },
	{PE, 0x6e00, TRUE,  0x50, 0x4c, FALSE, 0x1c, 0x3cf4, 0x1568, TRUE },
	{PE, 0x6e00, TRUE,  0x50, 0x4c, FALSE, 0x1c, 0x3d54, 0,      TRUE },
	{PE, 0x6e00, TRUE,  0x50, 0x4c, FALSE, 0x1c, 0x3d44, 0,      TRUE },
	{PE, 0x6e00, TRUE,  0x50, 0x4c, FALSE, 0x1c, 0x3d04, 0,      TRUE },
	{PE, 0x3000, TRUE,  0x50, 0x4c, FALSE, 0x1c, 0,      0,      TRUE },
	{PE, 0x3800, TRUE,  0x5a, 0x4c, TRUE,  0x1c, 0,      0,      TRUE },
	{PE, 0x3a00, TRUE,  0x5a, 0x4c, TRUE,  0x1c, 0,      0,      TRUE }
};




// flags
int pkZipMode = 0;
int dllIncluded = 1;
unsigned int fileCRC;

/* decompress the items in a WISE install executable */
int main(int argc, char* argv[])
{
  int r;
  int i;
  int fileVersion;
  char tmp[10];
  char tmp1[100];
  int compStart;

  // for the extracted file data
  char dllFileName[300];
  int dllFileSize;
  char flags[4];
  char colours[12];
  char extra[8];
  char archive[56];
  
  CONSTRUCTGLOBALS();

#ifdef MALLOC_WORK
  G.area.Slide = (uch *)calloc(8193, sizeof(short)+sizeof(char)+sizeof(char));
#endif


  // check command line args
  if (argc != 2)
  {
    err(1, "Syntax: exwise <filename>\n");
    DESTROYGLOBALS()
    EXIT(3);
  }

  // open file
  if ((G.in = fopen(argv[1], "rb")) == NULL)
    err(2, "Cannot open input file");

  // work out what version of installer we're dealing with
  i=0; 
  while(checkTable[i][0] != -1)
  {
    fseek(G.in, checkTable[i][0], SEEK_SET);
    fread(&r, 4, 1, G.in);
    if (r == checkTable[i][1])
    {
      // seek to the start of the data then
      fseek(G.in, checkTable[i][1], SEEK_SET);
      fileVersion = i;
      break;
    }
    i++;
  }

  if (checkTable[i][0] == -1)
    err(2, "Unknown WISE stub version OR not a WISE installer.");



  // see if a DLL filename was supplied
  r=0;
  fread(&r, 1, 1, G.in);
  if (r != 0)
  {
    fread(dllFileName, r, 1, G.in);
    fread(&dllFileSize, 4, 1, G.in);
    dllIncluded = 0;
  }

  // extract other data
  fread(flags, 4, 1, G.in);
  fread(colours, 12, 1, G.in);
  fread(extra, 8, 1, G.in);
  fread(archive, 56, 1, G.in);


  // check for PKZIP mode
  if (flags[1] & 1)
    pkZipMode = 1;

  // get the start of the compressed data
  compStart = ftell(G.in);

  // loop, extracting all the files
  i=0;
  while(1)
  {
    // extract a file
    switch(i)
    {
    case 0:
      sprintf(tmp1, "script.bin");
      i++;
      break;
      
    case 1:
      if (dllIncluded)
      {
	sprintf(tmp1, "wise0001.dll");
	i++;
	break;
      }
      // FALL THROUGH

    default:
      sprintf(tmp1, "file%i.bin", i++);
      break;
    }

    printf("Extracting file %s, startPos %x", tmp1, ftell(G.in) - compStart);
    fflush(stdout);

    fflush(stderr);
    out = fopen(tmp1, "wb");
    extract();
    fclose(out);


    // check for end of input file
    if (fread(tmp, 1, 4, G.in) != 4)
      break;

    // if we're in non-pkzip mode, this is the CRC of the file
    if (!pkZipMode)
      fileCRC = *((unsigned int*) tmp);

    // FIX for bug in inflate(), or original compressor
    // sometimes seems to be a byte ahead of where it should be
    if (!pkZipMode)
      if (fileCRC != G.crc32val)
      {
	fseek(G.in, -3, 1);
	fread(tmp, 1, 4, G.in);
	fileCRC = *((unsigned int*) tmp);
      }

    printf(", CRC %x, endPos %x\n", fileCRC, ftell(G.in) - compStart);
    fflush(stdout);

    // check CRCs
    if (fileCRC != G.crc32val)
      fprintf(stderr, "!!File %s corrupt!!\n", tmp1);

    // if we're in pkzip mode, we'll have the PK file table at the end...
    // check for this
    if (pkZipMode && ((tmp[0] != 'P') || (tmp[1] != 'K') ||
		      (tmp[2] != 3) || (tmp[3] != 4)))
      break;

    // if we're in PKzip mode, move back over those bytes, since we will need 
    // them
    if (pkZipMode)
      fseek(G.in, -4, 1);

    // non-pkZipMode check
    if (!pkZipMode)
      if (fread(tmp, 1, 4, G.in) != 4)
	break;
      else
	fseek(G.in, -4, 1);
  }

  /* cleanup & exit */
  DESTROYGLOBALS()
  RETURN (0);
}



void extract(void)
{
  int r;
  char tmp[0x1e];

  // skip PK header if in PKzip mode
  if (pkZipMode)
  {
    fread(tmp, 0x1e, 1, G.in);
    fseek(G.in, tmp[0x1a] | (tmp[0x1b] << 8), 1);
    fseek(G.in, tmp[0x1c] | (tmp[0x1d] << 8), 1);
    fileCRC = *((unsigned int*) (tmp+0xe));
  }

  /* prepare output buffer and crc */
  G.outptr = slide;
  G.outcnt = 0L;
  G.crc32val = CRCVAL_INITIAL;
  outsiz = 0L;

  /* deflate */
#ifdef USE_ZLIB
  /* need to allocate and prepare input buffer */
  if ((G.inbuf = (uch *)malloc(INBUFSIZ)) == (uch *)NULL)
    err(1, "out of memory");
#endif /* USE_ZLIB */
  if ((r = UZinflate(__G)) != 0)
    if (r == 3)
      err(1, "out of memory");
    else
      err(4, "invalid compressed data--format violated");
  inflate_free(__G);


  /* flush one last time; no need to reset G.outptr/outcnt */
  if (G.outcnt)   
  {
    G.crc32val = crc32(G.crc32val, slide, (extent)G.outcnt);
    if (fwrite((char *)slide, 1,(extent)G.outcnt,out) != (extent)G.outcnt
        && !PIPE_ERROR)
      err(9, "out of space on stdout");
    outsiz += G.outcnt;
  }
  fflush(out);
}
