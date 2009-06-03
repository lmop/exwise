{&Use32-}
Unit  Inflate ; {adapted for e_wise ! }

{
   This code is based on the following:

      "inflate.c -- Not copyrighted 1992 by Mark Adler"
      version c10p1, 10 January 1993

   Written 1995 by Oliver Fromme <fromme@rz.tu-clausthal.de>.
   Donated to the public domain.

   Freely distributable, freely usable.
   Nobody may claim copyright on this code.

   Disclaimer:  Use it at your own risk.  I am not liable for anything.

   Note that this is not my usual programming style, because of the
   conversion from C to Pascal.  Many things could have been implemented
   more efficient and in a more natural way if written from scratch in
   Pascal.  Especially the handling of pointers and arrays is awful in C.

   *** VERY IMPORTANT NOTES: ***

   1. This unit assumes that GetMem returns a NIL pointer if there is not
      enoug memory (no run-time error).  This requires a user-defined
      HeapError function which always returns 1.

   2. The application must allocate memory for the slide^[] array!
      Exactly WSIZE bytes have to be allocated.  This is _not_ done by this
      unit, so the application has to care about that.

   3. The application has to provide the InflateFlush function (interface
      section) which takes the first w bytes of the slide array as output
      of the inflate process.  It returns an error code:  0 = no error,
      any other value causes inflate to stop and return the same code.

   4. The application has to provide the InflateRead function which returns
      the next byte of the input stream which is fed into the inflate
      process.
}

{$A+,B-,I-,Q-,R-,S-,T-,V+,X+}
{$D+,L+,Y+} {for debugging only}

{
   The following text (and many of the comments) is from the original
   inflate code by Mark Adler.

   Inflate deflated (PKZIP's method 8 compressed) data.  The compression
   method searches for as much of the current string of bytes (up to a
   length of 258) in the previous 32K bytes.  If it doesn't find any
   matches (of at least length 3), it codes the next byte.  Otherwise, it
   codes the length of the matched string and its distance backwards from
   the current position.  There is a single Huffman code that codes both
   single bytes (called "literals") and match lengths.  A second Huffman
   code codes the distance information, which follows a length code.  Each
   length or distance code actually represents a base value and a number
   of "extra" (sometimes zero) bits to get to add to the base value.  At
   the end of each deflated block is a special end-of-block (EOB) literal/
   length code.  The decoding process is basically: get a literal/length
   code; if EOB then done; if a literal, emit the decoded byte; if a
   length then get the distance and emit the referred-to bytes from the
   sliding window of previously emitted data.

   There are (currently) three kinds of inflate blocks: stored, fixed, and
   dynamic.  The compressor outputs a chunk of data at a time, and decides
   which method to use on a chunk-by-chunk basis.  A chunk might typically
   be 32K to 64K, uncompressed.  If the chunk is uncompressible, then the
   "stored" method is used.  In this case, the bytes are simply stored as
   is, eight bits per byte, with none of the above coding.  The bytes are
   preceded by a count, since there is no longer an EOB code.

   If the data is compressible, then either the fixed or dynamic methods
   are used.  In the dynamic method, the compressed data is preceded by
   an encoding of the literal/length and distance Huffman codes that are
   to be used to decode this block.  The representation is itself Huffman
   coded, and so is preceded by a description of that code.  These code
   descriptions take up a little space, and so for small blocks, there is
   a predefined set of codes, called the fixed codes.  The fixed method is
   used if the block ends up smaller that way (usually for quite small
   chunks), otherwise the dynamic method is used.  In the latter case, the
   codes are customized to the probabilities in the current block, and so
   can code it much better than the pre-determined fixed codes can.

   The Huffman codes themselves are decoded using a mutli-level table
   lookup, in order to maximize the speed of decoding plus the speed of
   building the decoding tables.  See the comments below that precede the
   lbits and dbits tuning parameters.

   Notes beyond the 1.93a appnote.txt:

   1. Distance pointers never point before the beginning of the output
      stream.
   2. Distance pointers can point back across blocks, up to 32k away.
   3. There is an implied maximum of 7 bits for the bit length table and
      15 bits for the actual data.
   4. If only one code exists, then it is encoded using one bit.  (Zero
      would be more efficient, but perhaps a little confusing.)  If two
      codes exist, they are coded using one bit each (0 and 1).
   5. There is no way of sending zero distance codes--a dummy must be
      sent if there are none.  (History: a pre 2.0 version of PKZIP would
      store blocks with no distance codes, but this was discovered to be
      too harsh a criterion.)  Valid only for 1.93a.  2.04c does allow
      zero distance codes, which is sent as one code of zero bits in
      length.
   6. There are up to 286 literal/length codes.  Code 256 represents the
      end-of-block.  Note however that the static length tree defines
      288 codes just to fill out the Huffman codes.  Codes 286 and 287
      cannot be used though, since there is no length base or extra bits
      defined for them.  Similarily, there are up to 30 distance codes.
      However, static trees define 32 codes (all 5 bits) to fill out the
      Huffman codes, but the last two had better not show up in the data.
   7. Unzip can check dynamic Huffman blocks for complete code sets.
      The exception is that a single code would not be complete (see #4).
   8. The five bits following the block type is really the number of
      literal codes sent minus 257.
   9. Length codes 8,16,16 are interpreted as 13 length codes of 8 bits
      (1+6+6).  Therefore, to output three times the length, you output
      three codes (1+1+1), whereas to output four times the same length,
      you only need two codes (1+3).  Hmm.
  10. In the tree reconstruction algorithm, Code = Code + Increment
      only if BitLength(i) is not zero.  (Pretty obvious.)
  11. Correction: 4 Bits: # of Bit Length codes - 4     (4 - 19)
  12. Note: length code 284 can represent 227-258, but length code 285
      really is 258.  The last length deserves its own, short code
      since it gets used a lot in very redundant files.  The length
      258 is special since 258 - 3 (the min match length) is 255.
  13. The literal/length and distance code bit lengths are read as a
      single stream of lengths.  It is possible (and advantageous) for
      a repeat code (16, 17, or 18) to go across the boundary between
      the two sets of lengths.
}

Interface

Const  WSIZE = $8000 ;
   {window size--must be a power of two, and at least 32K for zip's deflate}

Type  InflateWindow  = Array [0..Pred(WSIZE)] Of Byte ;
      pInflateWindow = ^InflateWindow ;

Var  slide : pInflateWindow ;
     InflateFlush : Function (w : Word) : Integer ;
     InflateRead  : Function : Byte ;
     GoBackInSource : Procedure(w : Word);
     End_of_Input : Function : Boolean;

Function  InflateRun : Integer ;

Implementation

{
   Huffman code lookup table entry--this entry is four bytes for machines
   that have 16-bit pointers (e.g. PC's in the small or medium model).
   Valid extra bits are 0..13.  e == 15 is EOB (end of block), e == 16
   means that v is a literal, 16 < e < 32 means that v is a pointer to
   the next table, which codes e - 16 bits, and lastly e == 99 indicates
   an unused code.  If a code with e == 99 is looked up, this implies an
   error in the data.
}

Type  pInteger = ^Integer ;
      pWord = ^Word ;
      phuft = ^huft ;
      huft  = Record
                 e : Byte ; {number of extra bits or operation}
                 b : Byte ; {number of bits in this code or subcode}
                 v : Record {this odd Record is just for easier Pas2C}
                 Case Integer Of
                    0 : (n : Word) ; {literal, length base, or distance base}
                    1 : (t : phuft) {pointer to next level of table}
                 End
              End ;
      pphuft = ^phuft ;

{
   The inflate algorithm uses a sliding 32K byte window on the uncompressed
   stream to find repeated byte strings.  This is implemented here as a
   circular buffer.  The index is updated simply by incrementing and then
   and'ing with $7fff (32K-1).
   It is left to other modules to supply the 32K area.  It is assumed
   to be usable as if it were declared "slide : ^Array [0..32767] Of Byte".
}

Var  wp : Word ; {current position in slide}

{Tables for deflate from PKZIP's appnote.txt.}

Const  border : Array [0..18] Of Word {Order of the bit length code lengths}
              = (16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15) ;

       cplens : Array [0..30] Of Word {Copy lengths for literal codes 257..285}
              = (3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,
                 35,43,51,59,67,83,99,115,131,163,195,227,258,0,0) ;
                {note: see note #13 above about the 258 in this list.}

       cplext : Array [0..30] Of Word {Extra bits for literal codes 257..285}
              = (0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,
                 3,3,3,3,4,4,4,4,5,5,5,5,0,99,99) ; {99=invalid}

       cpdist : Array [0..29] Of Word {Copy offsets for distance codes 0..29}
              = (1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,
                 257,385,513,769,1025,1537,2049,3073,4097,6145,
                 8193,12289,16385,24577) ;

       cpdext : Array [0..29] Of Word {Extra bits for distance codes}
              = (0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,
                 7,7,8,8,9,9,10,10,11,11,
                 12,12,13,13) ;

{NEXTBYTE -> InflateRead}

Procedure  NEEDBITS (Var b : LongInt ; Var k : Byte ; n : Byte) ;
   Begin
      While k<n Do Begin
         b := b Or (LongInt(InflateRead) Shl k) ;
         Inc (k,8)
      End
   End {NEEDBITS} ;

Procedure  DUMPBITS (Var b : LongInt ; Var k : Byte ; n : Byte) ;
   Begin
      b := b Shr n ;
      Dec (k,n)
   End {DUMPBITS} ;

(*
   Macros for inflate() bit peeking and grabbing.

#define NEXTBYTE    (ReadByte(&bytebuf), bytebuf)
#define NEEDBITS(n) {while(k<(n)){b|=((ulg)NEXTBYTE)<<k;k+=8;}}
#define DUMPBITS(n) {b>>=(n);k-=(n);}

   The usage is:

        NEEDBITS(j)
        x = b & mask_bits[j];
        DUMPBITS(j)

   where NEEDBITS makes sure that b has at least j bits in it, and
   DUMPBITS removes the bits from b.  The macros use the variable k
   for the number of bits in b.  Normally, b and k are register
   variables for speed, and are initialized at the begining of a
   routine that uses these macros from a global bit buffer and count.

   If we assume that EOB will be the longest code, then we will never
   ask for bits with NEEDBITS that are beyond the end of the stream.
   So, NEEDBITS should not read any more bytes than are needed to
   meet the request.  Then no bytes need to be "returned" to the buffer
   at the end of the last block.

   However, this assumption is not true for fixed blocks--the EOB code
   is 7 bits, but the other literal/length codes can be 8 or 9 bits.
   (The EOB code is shorter than other codes becuase fixed blocks are
   generally short.  So, while a block always has an EOB, many other
   literal/length codes have a significantly lower probability of
   showing up at all.)  However, by making the first table have a
   lookup of seven bits, the EOB code will be found in that first
   lookup, and so will not require that too many bits be pulled from
   the stream.
*)

Var  bb : LongInt ; {bit buffer, unsigned}
     bk : Byte ; {bits in bit buffer}

{
   Huffman code decoding is performed using a multi-level table lookup.
   The fastest way to decode is to simply build a lookup table whose
   size is determined by the longest code.  However, the time it takes
   to build this table can also be a factor if the data being decoded
   is not very long.  The most common codes are necessarily the
   shortest codes, so those codes dominate the decoding time, and hence
   the speed.  The idea is you can have a shorter table that decodes the
   shorter, more probable codes, and then point to subsidiary tables for
   the longer codes.  The time it costs to decode the longer codes is
   then traded against the time it takes to make longer tables.

   This results of this trade are in the variables lbits and dbits
   below.  lbits is the number of bits the first level table for literal/
   length codes can decode in one step, and dbits is the same thing for
   the distance codes.  Subsequent tables are also less than or equal to
   those sizes.  These values may be adjusted either when all of the
   codes are shorter than that, in which case the longest code length in
   bits is used, or when the shortest code is *longer* than the requested
   table size, in which case the length of the shortest code in bits is
   used.

   There are two different values for the two tables, since they code a
   different number of possibilities each.  The literal/length table
   codes 286 possible values, or in a flat code, a little over eight
   bits.  The distance table codes 30 possible values, or a little less
   than five bits, flat.  The optimum values for speed end up being
   about one bit more than those, so lbits is 8+1 and dbits is 5+1.
   The optimum values may differ though from machine to machine, and
   possibly even between compilers.  Your mileage may vary.
}

Const  lbits = 9 ; {bits in base literal/length lookup table}
       dbits = 6 ; {bits in base distance lookup table}

{If BMAX needs to be larger than 16, then h and x[] should be LongInts.}

Const  BMAX = 16 ; {maximum bit length of any code (16 for explode)}
       N_MAX = 288 ; {maximum number of codes in any set}

Var  hufts : Word ; {track memory usage}

{
   Free the malloc'ed tables built by huft_build, which makes a linked
   list of the tables it made, with the links in a dummy first entry of
   each table.
}
Procedure  huft_free (
   t : phuft {table to free}
   ) ;

   Var  p,q : phuft ; {(register variables)}
        alloc_tmp : Word ;

   Begin
      {Go through linked list, freeing from the malloced (t[-1]) address.}
      p := t ;
      While p<>NIL Do BEgin
         Dec (p) ;
         q := p^.v.t ;
         Dec (Word(p),2) ;
         alloc_tmp := (pWord(p))^ ;
         FreeMem (p,alloc_tmp) ;
         p := q
      End
   End {huft_free} ;

{
   Given a list of code lengths and a maximum table size, make a set of
   tables to decode that set of codes.  Return zero on success, one if
   the given code set is incomplete (the tables are still built in this
   case), two if the input is invalid (all zero length codes or an
   oversubscribed set of lengths), and three if not enough memory.
}
Function  huft_build (
   b : pWord ;     {code lengths in bits (all assumed <= BMAX)}
   n : Word ;      {number of codes (assumed <= N_MAX)}
   s : Word ;      {number of simple-valued codes (0..s-1)}
   d : pWord ;     {list of base values for non-simple codes}
   e : pWord ;     {list of extra bits for non-simple codes}
   t : pphuft ;    {result: starting table}
   m : pInteger    {maximum lookup bits, returns actual}
   ) : Integer ;

   Var  a : Word ;                    {counter for codes of length k}
        c : Array [0..BMAX] Of Word ; {bit length count table}
        f : Word ;                    {i repeats in table every f entries}
        g : Integer ;                 {maximum code length}
        h : Integer ;                 {table level}
        i : Word ;                    {counter, current code (register variable)}
        j : Word ;                    {counter (register variable)}
        k : Integer ;                 {number of bits in current code (register variable)}
        l : Integer ;                 {bits per table (returned in m)}
        p : pWord ;                   {pointer into c[], b[], or v[] (register variable)}
        q : phuft ;                   {points to current table (register variable)}
        r : huft ;                    {table entry for structure assignment}
        u : Array [0..BMAX-1] Of phuft ;{table stack}
        v : Array [0..N_MAX-1] Of Word ;{values in order of bit length}
        w : Integer ;                 {bits before this table = (l*h) (register variable)}
        x : Array [0..BMAX] Of Word ; {bit offsets, then code stack}
        xp : pWord ;                  {pointer into x}
        y : Integer ;                 {number of dummy codes added}
        z : Word ;                    {number of entries in current table}
        alloc_tmp : Word ;
        phuft_tmp : phuft ;
        pword_tmp : pWord ;

   Begin
      {Generate counts for each bit length}
      FillChar (c,SizeOf(c),0) ;
      p := b ;
      i := n ;
      Repeat
         Inc (c[p^]) ; {assume all entries <= BMAX}
         Inc (p) ;
         Dec (i)
      Until i=0 ;
      If c[0]=n Then Begin {null input--all zero length codes}
         t^ := NIL ;
         m^ := 0 ;
         huft_build := 0 ;
         Exit
      End ;

      {Find minimum and maximum length, bound m^ by those}
      l := m^ ;
      For j:=1 To BMAX Do
         If c[j]<>0 Then
            Break ;
      k := j ; {minimum code length}
      If l<j Then
         l := j ;
      For i:=BMAX DownTo 1 Do
         If c[i]<>0 Then
            Break ;
      g := i ; {maximum code length}
      If l>i Then
         l := i ;
      m^:= l ;

      {Adjust last length count to fill out codes, if needed}
      y := 1 Shl j ;
      While j<i Do Begin
         Dec (y,c[j]) ;
         If y<0 Then Begin
            huft_build := 2 ; {bad input: more codes than bits}
            Exit
         End ;
         Inc (j) ;
         y := y Shl 1
      End ;
      Dec (y,c[i]) ;
      If y<0 Then Begin
         huft_build := 2 ; {bad input: more codes than bits}
         Exit
      End ;
      Inc (c[i],y) ;

      {Generate starting offsets into the value table for each length}
      x[1] := 0 ;
      j := 0 ;
      p := Addr(c[1]) ;
      xp := Addr(x[2]) ;
      Dec (i) ; {note that i=g from above}
      While i<>0 Do Begin
         Inc (j,p^) ;
         Inc (p) ;
         xp^ := j ;
         Inc (xp) ;
         Dec (i)
      End ;

      {Make a table of values in order of bit lengths}
      p := b ;
      i := 0 ;
      Repeat
         j := p^ ;
         Inc (p) ;
         If j<>0 Then Begin
            v[x[j]] := i ;
            Inc (x[j])
         End ;
         Inc (i)
      Until i>=n ;

      {Generate the Huffman codes and for each, make the table entries}
      x[0] := 0 ; {first Huffman code is zero}
      i := 0 ;
      p := Addr(v) ; {grab values in bit order}
      h := -1 ; {no tables yet--level -1}
      w := -l ; {bits decoded = (l*h)}
      u[0] := NIL ; {just to keep compilers happy}
      q := NIL ; {ditto}
      z := 0 ; {ditto}

      {go through the bit lengths (k already is bits in shortest code)}
      While k<=g Do Begin
         a := c[k] ;
         While (a<>0) Do Begin
            Dec (a) ;
            {here i is the Huffman code of length k bits for value *p}
            {make tables up to required level}
            While k>w+l Do Begin
               Inc (h) ;
               Inc (w,l) ; {previous table always l bits}
               {compute minimum size table less than or equal to l bits}
               If g-w>l Then {upper limit on table size}
                  z := l
               Else
                  z := g-w ;
               j := k-w ; {try a k-w bit table}
               f := 1 Shl j ;
               If f>a+1 Then Begin {too few codes for k-w bit table}
                  Dec (f,a+1) ; {deduct codes from patterns left}
                  xp := Addr(c[k]) ;
                  Inc (j) ;
                  While j<z Do Begin {try smaller tables up to z bits}
                     f := f Shl 1 ;
                     Inc (xp) ;
                     If f<=xp^ Then
                        Break ; {enough codes to use up j bits}
                     Dec (f,xp^) ; {else deduct codes from patterns}
                     Inc (j)
                  End ;
               End ;
               z := 1 Shl j ; {table entries for j-bit table}
               {allocate and link in new table}
               alloc_tmp := 2+(z+1)*SizeOf(huft) ;
               GetMem (q,alloc_tmp) ;
               If q=NIL Then Begin
                  If h<>0 Then
                     huft_free (u[0]) ;
                  huft_build := 3 ; {not enough memory}
                  Exit
               End ;
               pWord(q)^ := alloc_tmp ;
               Inc (Word(q),2) ;
               Inc (hufts,z+1) ; {track memory usage}
               t^ := q ; Inc (t^) ; {link to list for huft_free()}
               t := Addr(q^.v.t) ;
               t^ := NIL ;
               Inc (q) ;
               u[h] := q ; {table starts after link}
               {connect to last table, if there is one}
               If h<>0 Then Begin
                  x[h] := i ;        {save pattern for backing up}
                  r.b := l ;         {bits to dump before this table}
                  r.e := 16+j ;      {bits in this table}
                  r.v.t := q ;       {pointer to this table}
                  j := i Shr (w-l) ; {(get around Turbo C bug)}
                  {u[h-1][j] := r}
                  phuft_tmp := u[h-1] ;
                  Inc (phuft_tmp,j) ;
                  phuft_tmp^ := r     {connect to last table}
               End ;
            End ;
            {set up table entry in r}
            r.b := k-w ;
            If LongInt(p)>=LongInt(@(v[n])) Then
               r.e := 99 {out of values--invalid code}
            Else If p^<s Then Begin
               If p^<256 Then {256 is end-of-block code}
                  r.e := 16
               Else
                  r.e := 15 ;
               r.v.n := p^ ; {simple code is just the value}
               Inc (p)
            End
            Else Begin
               pword_tmp := e ;
               Inc (pword_tmp,p^-s) ;
               r.e := pword_tmp^ ; {non-simple--look up in lists}
               pword_tmp := d ;
               Inc (pword_tmp,p^-s) ;
               r.v.n := pword_tmp^ ;
               Inc (p)
            End ;
            {fill code-like entries with r}
            f := 1 Shl (k-w) ;
            j := i Shr w ;
            While j<z Do Begin
               phuft_tmp := q ;
               Inc (phuft_tmp,j) ;
               phuft_tmp^ := r ;
               Inc (j,f)
            End ;
            {backwards increment the k-bit code i}
            j := 1 Shl (k-1) ;
            While (i And j)<>0 Do Begin
               i := i XOr j ;
               j := j Shr 1
            End ;
            i := i XOr j ;
            {backup over finished tables}
            While (i And (1 Shl w -1)) <> x[h] Do Begin
               Dec (h) ; {don't need to update q}
               Dec (w,l)
            End ;

         End ;
         Dec (a) ;

         Inc (k)
      End ;
      {Return 1 if we were given an incomplete table}
      If (y<>0) And (g<>1) Then
         huft_build := 1
      Else
         huft_build := 0
   End {huft_build} ;

Const  mask_bits : Array [0..16] Of Word
                 = (0,1,3,7,15,31,63,127,255,511,1023,
                    2047,4095,8191,16383,32767,65535) ;

{
   inflate (decompress) the codes in a deflated (compressed) block.
   Return an error code or zero if it all goes ok.
}
Function  inflate_codes (
   tl,td : phuft ; {literal/length and distance decoder tables}
   bl,bd : Integer {number of bits decoded by tl[] and td[]}
   ) : Integer ;

   Var  e : Word ;     {table entry flag/number of extra bits (register variable)}
        n,d : Word ;   {length and index for copy}
        w : Word ;     {current window position}
        t : phuft ;    {pointer to table entry}
        ml,md : Word ; {masks for bl and bd bits}
        b : LongInt ;  {bit buffer (unsigned, register variable)}
        k : Byte ;     {number of bits in bit buffer (register variable)}
        i : Integer ;

   Begin
      {make local copies of globals}
      b := bb ; {initialize bit buffer}
      k := bk ;
      w := wp ; {initialize window position}
      {inflate the coded data}
      ml := mask_bits[bl] ; {precompute masks for speed}
      md := mask_bits[bd] ;
      While {VK::True}not End_of_Input Do Begin {do until end of block}
         NEEDBITS (b,k,bl) ;
         t := tl ;
         Inc (t,b And ml) ;
         e := t^.e ;
         If e>16 Then
            Repeat
               If e=99 Then Begin
                  inflate_codes := 1 ;
                  Exit
               End ;
               DUMPBITS (b,k,t^.b) ;
               Dec (e,16) ;
               NEEDBITS (b,k,e) ;
               t := t^.v.t ;
               Inc (t,b And mask_bits[e]) ;
               e := t^.e
            Until e<=16 ;
         DUMPBITS (b,k,t^.b) ;
         If e=16 Then Begin {it's a literal}
            slide^[w] := t^.v.n ;
            Inc (w) ;
            If w=WSIZE Then Begin
               i := InflateFlush(w) ;
               If i<>0 Then Begin
                  inflate_codes := i ;
                  Exit
               End ;
               w := 0
            End
         End
         Else Begin {it's an EOB or a length}
            {exit if end of block}
            If e=15 Then
               Break ;
            {get length of block to copy}
            NEEDBITS (b,k,e) ;
            n := t^.v.n+(b And mask_bits[e]) ;
            DUMPBITS (b,k,e) ;
            {decode distance of block to copy}
            NEEDBITS (b,k,bd) ;
            t := td ;
            Inc (t,b And md) ;
            e := t^.e ;
            If e>16 Then
               Repeat
                  If e=99 Then Begin
                     inflate_codes := 1 ;
                     Exit
                  End ;
                  DUMPBITS (b,k,t^.b) ;
                  Dec (e,16) ;
                  NEEDBITS (b,k,e) ;
                  t := t^.v.t ;
                  Inc (t,b And mask_bits[e]) ;
                  e := t^.e
               Until e<=16 ;
            DUMPBITS (b,k,t^.b) ;
            NEEDBITS (b,k,e) ;
            d := w-t^.v.n-Word(b And mask_bits[e]) ;
            DUMPBITS (b,k,e) ;
            {do the copy}
            Repeat
               d := d And (WSIZE-1) ;
               If d>w Then
                  e := WSIZE-d
               Else
                  e := WSIZE-w ;
               If e>n Then
                  e := n ;
               Dec (n,e) ;
               While e>0 Do Begin
                  slide^[w] := slide^[d] ;
                  Inc (w) ;
                  Inc (d) ;
                  Dec (e)
               End ;
               If w=WSIZE Then Begin
                  i := InflateFlush(w) ;
                  If i<>0 Then Begin
                     inflate_codes := i ;
                     Exit
                  End ;
                  w := 0
               End
            Until n=0 ;
         End
      End ;
      {restore the globals from the locals}
      wp := w ; {restore global window pointer}
      bb := b ; {restore global bit buffer}
      bk := k ;
      {done}
      inflate_codes := 0
   End {inflate_codes} ;

{
   "decompress" an inflated type 0 (stored) block.
}
Function inflate_stored : Integer ;

   Var  n : Word ;    {number of bytes in block}
        w : Word ;    {current window position}
        b : LongInt ; {bit buffer (unsigned, register variable)}
        k : Byte ;    {number of bits in bit buffer (register variable)}
        i : Integer ;

   Begin
      {make local copies of globals}
      b := bb ; {initialize bit buffer}
      k := bk ;
      w := wp ; {initialize window position}
      {go to byte boundary}
      n := k And 7 ;
      DUMPBITS (b,k,n) ;
      {get the length and its complement}
      NEEDBITS (b,k,16) ;
      n := (b And $ffff) ;
      DUMPBITS (b,k,16) ;
      NEEDBITS (b,k,16) ;
      If n<>((Not b) And $ffff) Then Begin
         inflate_stored := 1 ; {error in compressed data}
         Exit
      End ;
      DUMPBITS (b,k,16) ;
      {read and output the compressed data}
      While n<>0 Do Begin
         Dec (n) ;
         NEEDBITS (b,k,8) ;
         slide^[w] := b ;
         Inc (w) ;
         If w=WSIZE Then Begin
            i := InflateFlush(w) ;
            If i<>0 Then Begin
               inflate_stored := i ;
               Exit
            End ;
            w := 0
         End ;
         DUMPBITS (b,k,8)
      End ;
      {restore the globals from the locals}
      wp := w ;  {restore global window pointer}
      bb := b ;  {restore global bit buffer}
      bk := k ;
      inflate_stored := 0
   End {inflate_stored} ;

{
   decompress a deflated type 1 (fixed Huffman codes) block.  We should
   either replace this with a custom decoder, or at least precompute the
   Huffman tables.
}
Function  inflate_fixed : Integer ;

   Var  i : Integer ;  {temporary variable}
        tl : phuft ;   {literal/length code table}
        td : phuft ;   {distance code table}
        bl : Integer ; {lookup bits for tl}
        bd : Integer ; {lookup bits for td}
        l : Array [0..287] Of Word ; {length list for huft_build}

   Begin
      {set up literal table}
      For i:=0 To 143 Do
         l[i] := 8 ;
      For i:=144 To 255 Do
         l[i] := 9 ;
      For i:=256 To 279 Do
         l[i] := 7 ;
      For i:=280 To 287 Do {make a complete, but wrong code set}
         l[i] := 8 ;
      bl := 7 ;
      i := huft_build(@l,288,257,@cplens,@cplext,Addr(tl),Addr(bl)) ;
      If i<>0 Then Begin
         inflate_fixed := i ;
         Exit
      End ;
      {set up distance table}
      For i:=0 To 29 Do {make an incomplete code set}
         l[i] := 5 ;
      bd := 5 ;
      i := huft_build(@l,30,0,@cpdist,@cpdext,Addr(td),Addr(bd)) ;
      If i>1 Then Begin
         huft_free (tl) ;
         inflate_fixed := i ;
         Exit
      End ;
      {decompress until an end-of-block code}
      i := inflate_codes(tl,td,bl,bd) ;
      If i<>0 Then Begin
         inflate_fixed := i ;
         huft_free (tl) ;
         huft_free (td) ;
         Exit
      End ;
      {free the decoding tables, return}
      huft_free (tl) ;
      huft_free (td) ;
      inflate_fixed := 0
   End {inflate_fixed} ;

{
   decompress an inflated type 2 (dynamic Huffman codes) block.
}
Function  inflate_dynamic : Integer ;

   Var  i : Integer ;  {temporary variables}
        j : Word ;
        l : Word ;     {last length}
        m : Word ;     {mask for bit lengths table}
        n : Word ;     {number of lengths to get}
        tl : phuft ;   {literal/length code table}
        td : phuft ;   {distance code table}
        bl : Integer ; {lookup bits for tl}
        bd : Integer ; {lookup bits for td}
        nb : Word ;    {number of bit length codes}
        nl : Word ;    {number of literal/length codes}
        nd : Word ;    {number of distance codes}
        ll : Array [0..286+30-1] Of Word ;  {literal/length and distance code lengths}
        b : LongInt ;  {bit buffer (unsigned, register variable)}
        k : Byte ;     {number of bits in bit buffer (register variable)}

   Begin
      {make local bit buffer}
      b := bb ;
      k := bk ;
      {read in table lengths}
      NEEDBITS (b,k,5) ;
      nl := 257+(b And $1f) ; {number of literal/length codes}
      DUMPBITS (b,k,5) ;
      NEEDBITS (b,k,5) ;
      nd := 1+(b And $1f) ; {number of distance codes}
      DUMPBITS (b,k,5) ;
      NEEDBITS (b,k,4) ;
      nb := 4+(b And $f) ; {number of bit length codes}
      DUMPBITS (b,k,4) ;
      If (nl>286) Or (nd>30) Then Begin
         inflate_dynamic := 1 ; {bad lengths}
         Exit
      End ;
      {read in bit-length-code lengths}
      For j:=0 To nb-1 Do Begin
         NEEDBITS (b,k,3) ;
         ll[border[j]] := b And 7 ;
         DUMPBITS (b,k,3)
      End ;
      For j:=nb To 18 Do
         ll[border[j]] := 0 ;
      {build decoding table for trees--single level, 7 bit lookup}
      bl := 7 ;
      i := huft_build(@ll,19,19,NIL,NIL,Addr(tl),Addr(bl)) ;
      If i<>0 Then Begin
         If i=1 Then
            huft_free (tl) ;
         inflate_dynamic := i ; {incomplete code set}
         Exit
      End ;
      {read in literal and distance code lengths}
      n := nl+nd ;
      m := mask_bits[bl] ;
      l := 0 ;
      i := 0 ;
      While i<n Do Begin
         NEEDBITS (b,k,bl) ;
         td := tl ;
         Inc (td,b And m) ;
         j := td^.b ;
         DUMPBITS (b,k,j) ;
         j := td^.v.n ;
         If j<16 Then Begin {length of code in bits (0..15)}
            l := j ; {save last length in l}
            ll[i] := j ;
            Inc (i)
         End
         Else If j=16 Then Begin {repeat last length 3 to 6 times}
            NEEDBITS (b,k,2) ;
            j := 3+(b And 3) ;
            DUMPBITS (b,k,2) ;
            If i+j>n Then Begin
               inflate_dynamic := 1 ;
               Exit
            End ;
            While j<>0 Do Begin
               Dec (j) ;
               ll[i] := l ;
               Inc (i)
            End ;
            Dec (j)
         End
         Else If j=17 Then Begin {3 to 10 zero length codes}
            NEEDBITS (b,k,3) ;
            j := 3+(b And 7) ;
            DUMPBITS (b,k,3) ;
            If i+j>n Then Begin
               inflate_dynamic := 1 ;
               Exit
            End ;
            While j<>0 Do Begin
               Dec (j) ;
               ll[i] := 0 ;
               Inc (i)
            End ;
            Dec (j) ;
            l := 0
         End
         Else Begin {j=18: 11 to 138 zero length codes}
            NEEDBITS (b,k,7) ;
            j := 11+(b And $7f) ;
            DUMPBITS (b,k,7) ;
            If i+j>n Then Begin
               inflate_dynamic := 1 ;
               Exit
            End ;
            While j<>0 Do Begin
               Dec (j) ;
               ll[i] := 0 ;
               Inc (i)
            End ;
            Dec (j) ;
            l := 0
         End
      End ;
      {free decoding table for trees}
      huft_free (tl) ;
      {restore the global bit buffer}
      bb := b ;
      bk := k ;
      {build the decoding tables for literal/length and distance codes}
      bl := lbits ;
      i := huft_build(@ll,nl,257,@cplens,@cplext,Addr(tl),Addr(bl)) ;
      If i<>0 Then Begin
         if i=1 Then
            huft_free (tl) ;
         inflate_dynamic := i ; {incomplete code set}
         Exit
      End ;
      bd := dbits ;
      i := huft_build(@(ll[nl]),nd,0,@cpdist,@cpdext,Addr(td),Addr(bd)) ;
      If i<>0 Then Begin
         if i=1 Then
            huft_free (td) ;
         huft_free (tl) ;
         inflate_dynamic := i ; {incomplete code set}
         Exit
      End ;
      {decompress until an end-of-block code}
      i := inflate_codes(tl,td,bl,bd) ;
      If i<>0 Then Begin
         inflate_dynamic := i ;
         huft_free (tl) ;
         huft_free (td) ;
         Exit
      End ;
      {free the decoding tables, return}
      huft_free (tl) ;
      huft_free (td) ;
      inflate_dynamic := 0
   End {inflate_dynamic} ;

{
   decompress an inflated block
}
Function  inflate_block (
   e : pInteger {last block flag}
   ) : Integer ;

   Var  t : Word ;    {block type}
        b : LongInt ; {bit buffer (unsigned, register variable)}
        k : Byte ;    {number of bits in bit buffer (register variable)}

   Begin
      {make local bit buffer}
      b := bb ;
      k := bk ;
      {read in last block bit}
      NEEDBITS (b,k,1) ;
      e^ := b And 1 ;
      DUMPBITS (b,k,1) ;
      {read in block type}
      NEEDBITS (b,k,2) ;
      t := b And 3 ;
      DUMPBITS (b,k,2) ;
      {restore the global bit buffer}
      bb := b ;
      bk := k ;
      {inflate that block type}
      Case t Of
         2 : inflate_block := inflate_dynamic ;
         0 : inflate_block := inflate_stored ;
         1 : inflate_block := inflate_fixed
      Else
         inflate_block := 2 {bad block type}
      End
   End {inflate_block} ;

{
   decompress an inflated entry
}
Function  InflateRun : Integer ;

   Var  e : Integer ; {last block flag}
        r : Integer ; {result code}
        h : Word ;    {maximum struct huft's malloc'ed}

   Begin
      {initialize window, bit buffer}
      wp := 0 ;
      bk := 0 ;
      bb := 0 ;
      {decompress until the last block}
      h := 0 ;
      Repeat
         hufts := 0 ;
         r := inflate_block(Addr(e)) ;
         if r<>0 Then Begin
            InflateRun := r ;
            Exit
         End ;
         If hufts>h Then
            h := hufts
      Until e<>0 ;
      {flush out slide, return error code}
      InflateRun := InflateFlush(wp);
      if bk>=8 then
        GoBackInSource(bk shr 3);
   End {InflateRun} ;

Begin
   slide := NIL
End.
