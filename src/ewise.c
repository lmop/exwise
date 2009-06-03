#include <glib.h>
/*
{&Use32-}
program E_WISE;

(* 1999.12.18 Veit Kannegieser mit inflate-pascal.zip/DumPING als Grundlage *)
(* 1999.12.19..2000.02.06 Erstversion aus e_lc10                            *)
(* 2000.02.11 NE/$3e10 hinzugefgt                                          *)
(* 2000.02.18 NE/$3bd0 und NE/$3c10 hinzugefgt                             *)
(* 2000.02.28 Untersttzung fr selbstauspackende Selbstauspacker ...       *)
(*            Verbesserte Dateinamenerkennung                               *)
(* 2000.03.01 Problem mit PE_0FEC:PE_6E00 behoben (Relokationen wurden      *)
(*            nicht mitgerechnet)                                           *)
(* 2000.08.21 NE/$3770 hinzugefgt,stOpen->stOpenRead                       *)
(* 2000.10.12 Behandlung von Nullen in der letzten Datei gendert           *)
(* 2000.12.08 -                                                             *)
(* 2001.05.21 PE/$6e00/$3cf4 -> ../$1528 und ../$1568                       *)
(* 2002.02.11 NE/$84b0, Debugmodus                                          *)
(* 2002.03.26 NE/$3c20 von Ralph Roth                                       *)
(* 2002.03.29 PE/6e00,$3d04, Lade bekannte Format aus e_wise.ini            *)
(* 2002.06.30 Dateinamen mit & werden mit "" verpackt                       *)
(*            NE/37b0 von Cristian Salvari                                  *)
(*      07.01 Verbesserte Behandlung des Patchformates                      *)
(*            Einmalige Dateinamen                                          *)

{
   Copyright (c) 1995 by Oliver Fromme  --  All Rights Reserved

   Address:  Oliver Fromme, Leibnizstr. 18-61, 38678 Clausthal, Germany
   Internet:  fromme@rz.tu-clausthal.de
   WWW:  http://www.tu-clausthal.de/~inof/

   Freely distributable, freely usable.
   The original copyright notice may not be modified or omitted.
}

{$A+,B-,D+,E-,F-,G+,I+,L+,N-,O-,P-,Q-,R-,S-,T-,V+,X+,Y+}
(*$M 80000*)
(*$AlignRec-*)

uses
//  Crt,
  VpUtils,
  ExeHdr,
  crc32,
  inflate,
  Objects,
  Strings,
  Dos,
  VpSysLow,
  e_wi_spr;
*/
  
//according to http://support.microsoft.com/kb/65122
struct exe_header
{
	guint16 signature;               //00-01
	guint16 bytes_in_last_block;     //02-03     
	guint16 blocks_in_file;          //04-05 
	guint16 num_relocs;              //06-07
	guint16 paragraph_count;         //08-09
	guint16 min_extra_paragraphs;    //0A-0B
	guint16 max_extra_paragraphs;    //0C-0D
	guint16 ss;                      //0E-0F
	guint16 sp;                      //10-11
	guint16 checksum;                //12-13
	guint16 ip;                      //14-15
	guint16 cs;                      //16-17
	guint16 reloc_table_offset;      //18-19
	guint16 overlay_number;          //1A-1B
	guint8 _dummy[0x3B-0x1C];              //1C-3B	
	guint64 segmented_header_offset; //3C-3F
};

struct segmented_exe_header /* new .EXE header */
{
    guint16 signature;                 //00-01 guint16
    guint8  version;                   //02
    guint8  revision;                  //03
    guint16 entry_table_offset;        //04-05 relative to segmented header
    guint16 entry_table_bytes;         //06-07
    guint32 file_crc;                  //08-0B
    guint16 flags;                     //0C-0D
    guint16 auto_data_segment_number;  //0E-0F
    guint16 heap_bytes;                //10-11 Initial heap allocation
    guint16 stack_bytes;               //12-13 Initial stack allocation
    guint32 csip;                      //14-18
    guint32 sssp;                      //19-1B
    guint16 file_segment_count;        //1C-1D
    guint16 module_entry_count;        //1E-1F
    guint16 non_resident_bytes;        //20-21
    guint16 segment_table_offset;      //22-23
    guint16 resource_table_offset;     //24-25
    guint16 resident_table_offset;     //26-27
    guint16 module_table_offset;       //28-29
    guint16 imported_table_offset;     //2A-2B
    guint32 non_resident_table_offset; //2C-2F
    guint16 movable_entry_count;       //30-31
    guint16 segment_align_shift_count; //32-33
    guint16 resource_entry_count;      //34-35
    guint8  executable_type;           //36
	//guint8  _dummy[0x3F-0x37];       //37-3F
};

struct segment_table
{
	guint16 logical_sector_offset;
    guint16 segment_bytes;
    guint16 flags;
    guint16 min_alloc_bytes;
};

struct ImageFileHeader
{
	guint16 machine;
	guint16 section_count;
	guint32 time_date_stamp;
	guint32 pointer_to_symbol_table;
	guint32 symbol_count;
	guint16 optional_header_size;
	guint16 characteristics;
};

struct ImageOptionalHeader
{
	guint16 magic;
	guint8 major_linker_version;
	guint8 minor_linker_version;
	guint32 size_of_code;
	guint32 size_of_initialized_data;
	guint32 size_of_uninitialized_data;
	guint32 address_of_entry_point;
	guint32 base_of_code;
	guint32 base_of_data;
	guint32 image_base;
	guint32 section_alignment;
	guint32 file_alignment;
	guint16 major_operating_system_version;
	guint16 minor_operating_system_version;
	guint16 major_image_version;
	guint16 minor_image_version;
	guint16 major_subsystem_version;
	guint16 minor_subsystem_version;
	guint32 win32_version_value;
	guint32 size_of_image;
	guint32 size_of_headers;
	guint32 checksum;
	guint16 subsystem;
	guint16 dll_characteristics;
	guint32 size_of_stack_reserve;
	guint32 size_of_stack_commit;
	guint32 size_of_heap_reserve;
	guint32 size_of_heap_commit;
	guint32 loader_flags;
	guint32 number_of_rva_and_sizes;
};

struct ImageSectionHeader
{
	guint8 name[8];
	union {
		guint32 physical_address;
		guint32 virtual_size;
	} misc;
	guint32 virtual_address;
	guint32 size_of_raw_data;
	guint32 pointer_to_raw_data;
	guint32 pointer_to_relocations;
	guint32 pointer_to_linenumbers;
	guint16 number_of_relocations;
	guint16 number_of_linenumbers;
	guint32 characteristics;
};

/*
const
  datum='1999.12.19..2002.07.01';
  kurzformat            =true;
  debugmodus    :boolean=false;
  buffersize            =512*1024;

type
  datei_information=
    record
      archivstart       :longint;
      laenge_eingepackt :longint;
      dateilaenge       :longint;
      dateilaenge_2     :longint; (* zur Anzeige ?/in der bersichttsdatei verwendet *)
      anfang            :array[0..400] of byte;
      dateiname         :string;
    end;

  datei_tabelle_typ     =array[1..10000] of datei_information;

  PLongint              =^longint;
  PWord                 =^smallword;

var
  d1,d2                 :pBufStream;
  d3                    :file;
  d1_laenge             :longint;
  crc                   :tCRC;
  datenbasis            :longint;
  datenstart            :longint;
  archivende            :longint;
  archivende_geladen    :longint;
  datei_tabelle         :^datei_tabelle_typ;
  dateizaehler          :longint;
  dateiname             :string;
  informationen         :PByteArray;
  informationslaenge    :longint;
  gefunden              :boolean;
  ausgewaehltes_format  :longint;
  gefundene_exe         :exe_typ_typ;
  zeit                  :longint;
  gepackter_datei_anfang:array[0..1] of longint;
  setup_programmcode_laenge,
  setup_programmdaten_laenge
                        :longint;
  dateinamen_erkannt    :boolean;
  neue_position_zk      :string;
  neue_position         :longint;
  kontrolle             :longint;

  bekannte_formate      :^bekannte_formate_typ;
  zahl_bekannte_formate :word;

const
  rechnungs_null        :longint=0;
  rechnungs_null_bekannt:boolean=false;
*/

enum exe_type
{
	UNKNOWN,
	NE,
	PE
};

struct wise_format
{
	enum exe_type type; //NE | PE
	size_t exec_length; //length of executable part
	gboolean has_dll_name; 
	size_t header_size;
	int archive_size_offset; //offset of archive size field | -1
	gboolean has_text_strings;
	int filename_offset;     //offset of filename in archive information file | -1
	size_t exe_code_size;
	size_t exe_data_size;
	gboolean crc_present;
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

/*
procedure obj_fehlerbehandlung(const f:longint);
  begin
    if f=stOk then exit;

    case f of
      stError:
        WriteLn(textz_access_error^);
      stInitError:
        WriteLn(textz_Cannot_initialize_stream^);
      stReadError:
        WriteLn(textz_Read_beyond_end_of_stream^);
      stWriteError:
        WriteLn(textz_Cannot_expand_stream^);
      stGetError:
        WriteLn('Get of unregistered object type');
      stPutError:
        WriteLn('Put of unregistered object type');
    end;
    RunError(f);
  end;
*/
/*
procedure d1_Read(var p;const anzahl:longint);
  begin
    //write(^h^h^h^h^h^h^h^h,Int2hex(d1^.getpos,8));
    FillChar(p,anzahl,0);
    d1^.Read(p,anzahl);
    d1^.status:=stok;
    obj_fehlerbehandlung(d1^.Status);
  end;

procedure d1_Seek(const position:longint);
  begin
    d1^.Seek(position);
    obj_fehlerbehandlung(d1^.Status);
  end;


function  d1_GetPos:longint;
  begin
    d1_GetPos:=d1^.GetPos;
    obj_fehlerbehandlung(d1^.Status);
  end;

procedure d2_Write(var p;const anzahl:longint);
  begin
    d2^.Write(p,anzahl);
    obj_fehlerbehandlung(d2^.Status);
  end;

function leer_sicherung(const zk:string):string;
  begin
    if (Pos(' ',zk)=0) and (Pos('&',zk)=0) then
      leer_sicherung:=zk
    else
      leer_sicherung:='"'+zk+'"';
  end;

function dname(const n:longint):string;
  begin
    dname:=Int2StrZ(n,8)+'.EWI';
  end;
*/
/*
procedure uebergehe_ne;
*/
GError* skip_ne(GIOChannel* input, enum exe_type* type, gint64* pBase, gint64* pStart, guint16* p_setup_code_bytes, guint16* p_setup_data_bytes)
{
/*
    var
      ne                :new_exe;
      rs_align          :smallword;
      rs_type           :rsrc_typeinfo;
      rs_name           :rsrc_nameinfo;
      a                 :longint;
      z1,z2             :longint;
      o                 :longint;
      codeseginfo,
      datenseginfo      :new_seg;
*/
	gint64 base = *pBase;
	gint64 start = *pStart;

	GError* error = NULL;
	gsize bytes_read = 0;
/*
      d1_Seek(datenbasis+datenstart);
*/
	GIOStatus status = g_io_channel_seek_position
	(
		input, base + start, G_SEEK_SET, &error
	);
		
	if(error)
		return error;
/*
      d1_Read(ne,SizeOf(ne));
*/
	struct segmented_exe_header header;
	
	status = g_io_channel_read_chars
	(
		input, &header, sizeof(header), &bytes_read, &error
	);
		
	if(error)
		return error;
/*
      o:=datenstart;
*/
	gint64 o = start;
/*
      d1_Seek(datenbasis+datenstart+ne.ne_segtab+0*SizeOf(new_seg));
*/
	status = g_io_channel_seek_position
	(
		input, base + start + header.segment_table_offset, G_SEEK_SET,	&error
	);
/*	
      d1_Read(codeseginfo,SizeOf(codeseginfo));
*/
	struct segment_table segment;
	status = g_io_channel_read_chars
	(
		input, &segment, sizeof(segment), &bytes_read, &error
	);
/*
      setup_programmcode_laenge:=codeseginfo.ns_cbseg;
*/
	*p_setup_code_bytes = segment.segment_bytes;
/*
      d1_Seek(datenbasis+datenstart+ne.ne_segtab+2*SizeOf(new_seg));
*/
	status = g_io_channel_seek_position
	(
		input, base + start + header.segment_table_offset + 2 * sizeof(struct segment_table), G_SEEK_SET,	&error
	);
/*
      d1_Read(datenseginfo,SizeOf(datenseginfo));
*/
	status = g_io_channel_read_chars
	(
		input, &segment, sizeof(segment), &bytes_read, &error
	);
/*
      setup_programmdaten_laenge:=datenseginfo.ns_cbseg;
*/
	*p_setup_data_bytes = segment.segment_bytes;

/*
      (* Annahme: es sind Resourcen vorhanden und sie sind am Ende.. *)
*/
	//let's assume resources are present at the end..
/*
      d1_Seek(datenbasis+datenstart+ne.ne_rsrctab);
*/
	status = g_io_channel_seek_position
	(
		input, base + start + header.resource_table_offset, G_SEEK_SET,	&error
	);
/*
      d1_Read(rs_align,SizeOf(rs_align));
*/
	status = g_io_channel_read_chars
	(
		input, ???, ????, &bytes_read, &error
	);
/*
      (* ne.ne_cres ist 0 also mu geschummelt werden *)
*/

	//since ne.ne_cs is 0 we have to cheat
      while d1_GetPos+SizeOf(rs_type)<=datenbasis+datenstart+ne.ne_restab do
        begin
          d1_Read(rs_type,SizeOf(rs_type));
          for z2:=1 to rs_type.rt_nres do
            begin
              d1_Read(rs_name,SizeOf(rs_name));
              a:=rs_name.rn_offset shl rs_align
                +rs_name.rn_length shl rs_align;
              if o<a then
                o:=a;
            end;
        end;
/*
      datenstart:=o;
*/
	*pStart = o;
/*
      gefundene_exe:=exe_ne;
*/
	*type = NE;
}

/*
procedure uebergehe_pe;
*/
GError* skip_pe(GIOChannel* input, enum exe_type* type, gint64* pBase, gint64* pStart, guint16* p_setup_code_bytes, guint16* p_setup_data_bytes)
{
/*
    var
      im                :TImageFileHeader;
      imo               :TImageOptionalHeader;
      sek               :TImageSectionHeader;
      r_bereich         :array[0..20000] of byte;
      f                 :longint;
      resource_sektion  :longint;
    type
      exe_hdr_z         =^exe_hdr;
*/
	GError* error = NULL;
	gint64 base = *pBase;
	gint64 start = *pStart;
	gsize bytes_read = 0;
/*
      d1_Seek(datenbasis+datenstart+4);
*/
	GIOStatus status = g_io_channel_seek_position
	(
		input, base + start + 4,
		G_SEEK_SET,	&error
	);
	
	if(error)
		return error;
/*
      d1_Read(im,SizeOf(im));
*/
	struct ImageFileHeader file_header;
	status = g_io_channel_read_chars
	(
		input, &file_header, sizeof(file_header), &bytes_read, &error
	);
		
	if(error)
		return error;
/*
      d1_Read(imo,SizeOf(imo));
*/
	struct ImageOptionalHeader optional_header;
	status = g_io_channel_read_chars
	(
		input, &optional_header, sizeof(optional_header), &bytes_read, &error
	);
		
	if(error)
		return error;
/*
      (* Informationen ber die erste Sektioen (.text) einlesen *)
      d1_Seek(datenbasis+datenstart+4+SizeOf(im)+im.SizeOfOptionalHeader);
*/
	//read information about the first sector (.text)
  	status = g_io_channel_seek_position
	(
		input, base + start + 4 + sizeof(file_header) + file_header.optional_header_size, G_SEEK_SET, &error
	);
	
	if(error)
		return error;
/*
      d1_Read(sek,SizeOf(sek));
*/
	struct ImageSectionHeader section_header;
	status = g_io_channel_read_chars
	(
		input, &section_header, sizeof(section_header), &bytes_read, &error
	);
	
	if(error)
		return error;
/*
      setup_programmcode_laenge:=sek.Misc.VirtualSize;
*/
	*p_setup_code_bytes = section_header.misc.virtual_size;
/*	
      d1_Seek(datenbasis+datenstart+4+SizeOf(im)+im.SizeOfOptionalHeader+2*SizeOf(sek));
*/
  	status = g_io_channel_seek_position
	(
		input, base + start + 4 + sizeof(file_header) + file_header.optional_header_size + 2 * sizeof(section_header), G_SEEK_SET, &error
	);
	
	if(error)
		return error;
/*
      d1_Read(sek,SizeOf(sek));
*/
	status = g_io_channel_read_chars
	(
		input, &section_header, sizeof(section_header), &bytes_read, &error
	);
/*
      setup_programmdaten_laenge:=sek.Misc.VirtualSize;
*/
	*p_setup_data_bytes = section_header.misc.virtual_size;
	
	if(error)
		return error;
/*
      (* Informationen ၁ber letzte Sektion (Resource..) einlesen *)
*/
		//read information about last section (Resource..)
/*
      resource_sektion:=im.NumberOfSections-1;
*/
	guint16 resource_section = file_header.section_count - 1;
/*
      if (im.Characteristics and (1 shl 0))=0 then
        Dec(resource_sektion); (* relo *)
*/
	if(!file_header.characteristics)
		resource_section--;
/*
      d1_Seek(datenbasis+datenstart+4+SizeOf(im)+im.SizeOfOptionalHeader+resource_sektion*SizeOf(sek));
*/
	status = g_io_channel_seek_position
	(
		input, base + start + 4 + sizeof(file_header) + file_header.optional_header_size + resource_section * sizeof(section_header), G_SEEK_SET, &error
	);
	
	if(error)
		return error;
/*
      d1_Read(sek,SizeOf(sek));
*/
	status = g_io_channel_read_chars
	(
		input, &section_header, sizeof(section_header), &bytes_read, &error
	);
		
	if(error)
		return error;
/*
      (* der Entpacker des Selbstentpackers benutzt auch keine Resourcefunktionen .. *)
*/
		//even original wise unpacker does not use resourcefunctions
      if sek.SizeOfRawData>SizeOf(r_bereich) then
        begin
          d1_Seek(datenbasis+sek.PointerToRawData);
          d1_Read(r_bereich,SizeOf(r_bereich));
          f:=0;
          while f<=High(r_bereich)-$80 do
            with exe_hdr_z(@r_bereich[f])^ do
              if ((e_magic=ExeId) or (e_magic=$4d5a))
              and (e_cparhdr>=4)
              and (e_lfanew>=$40)
              and ((e_crlc=0) or (e_crlc=3))
               then
                begin
                  datenstart:=sek.PointerToRawData+f;
                  archivende:=datenbasis+sek.PointerToRawData+imo.DataDirectory[image_Directory_Entry_Resource].Size;
                  search_finished = FALSE;
                  Exit;
                end
              else
                Inc(f);
        end;

/*
      d1_Seek(datenbasis+datenstart+4+SizeOf(im)+im.SizeOfOptionalHeader+(im.NumberOfSections-1)*SizeOf(sek));
*/
	status = g_io_channel_seek_position
	(
		input, base + start + 4 + sizeof(file_header) + file_header.optional_header_size + (file_header.section_count - 1) * sizeof(section_header), G_SEEK_SET, &error
	);
	
	if(error)
		return error;
/*
      d1_Read(sek,SizeOf(sek));
*/
	status = g_io_channel_read_chars
	(
		input, &section_header, sizeof(section_header), &bytes_read, &error
	);
	
	if(error)
		return error;
/*
      datenstart:=sek.PointerToRawData+sek.SizeOfRawData;
*/
	start = section_header.pointer_to_raw_data + section_header.size_of_raw_data;
/*
      gefundene_exe:=exe_pe;
*/
	*type = PE;
}
/*
procedure springe_zu_den_daten;
*/
GError* skip_to_data(GIOChannel* input, enum exe_type* type, gint64* pBase, gint64* pStart, guint16* p_setup_code_bytes, guint16* p_setup_data_bytes)
{
/*
  var
    exe_kopf            :exe_hdr;
    nochmal_ende_suchen :boolean;

    datenbasis:=0;
    datenstart:=0;
*/
	gint64 base = *pBase;
	gint64 start = *pStart;
/*	
    setup_programmcode_laenge:=0;
*/
	gboolean search_finished;
	
	GError* error = NULL; 
	GIOStatus status;
	gchar* buffer = NULL;
	gsize bytes_read = 0;
	
	do
    {
		search_finished = TRUE;

/*		
      Inc(datenbasis,datenstart);
*/
		base += start;
		start = 0;
/*
      gefundene_exe:=exe_unbekannt;
*/
		*type = UNKNOWN;
/*
      d1_Seek(datenbasis+datenstart);
*/
		status = g_io_channel_seek_position
		(
			input, base + start, G_SEEK_SET,	&error
		);
		
		if(error)
			return error;
/*
      d1_Read(exe_kopf,SizeOf(exe_kopf));
*/
		struct exe_header header;
		
		status = g_io_channel_read_chars
		(
			input, &header, sizeof(header), &bytes_read, &error
		);
		
		if(error)
			return error;
/*
      if ((exe_kopf.e_magic=ExeId) or (exe_kopf.e_magic=0x4d5a))
      and (exe_kopf.e_cparhdr>=4)
      and (exe_kopf.e_lfanew>=0x40)
       then
*/
		if
		(
			(/*(header->signature = ExeId) ||*/ (header.signature = 0x4d5a))
			&& (header.paragraph_count >= 4)
			&& (header.segmented_header_offset >= 0x40)
		)
		{
/*	
          datenstart:=exe_kopf.e_lfanew;
*/
			start = header.segmented_header_offset;
/*
          d1_Seek(datenbasis+datenstart);
*/
			status = g_io_channel_seek_position
			(
				input, base + start, G_SEEK_SET, &error
			);
			
			if(error)
				return error;
/*
          d1_Read(exe_kopf,SizeOf(exe_kopf));
*/
          	status = g_io_channel_read_chars
			(
				input, &header, sizeof(header), &bytes_read, &error
			);
			
			if(error)
				return error;
		}
/*
      case exe_kopf.e_magic of
        Ord('N')+Ord('E') shl 8:uebergehe_ne;
        Ord('P')+Ord('E') shl 8:uebergehe_pe;
      end;
*/
#define SIG_NE 'N' + ('E' << 8)
#define SIG_PE 'P' + ('E' << 8)
		
		switch(header.signature)
		{
			case NE:
      			skip_ne(input, type, &base, &start, p_setup_code_bytes, p_setup_data_bytes);
      			break;
      		case PE:
      			skip_pe(input, type, &base, &start, p_setup_code_bytes, p_setup_data_bytes);
      			break;
      		default:
      		{
      			//we're in trouble
      			error = g_error_new(0, 0, "Magic is %0x - expected %0x%0x or %0x%0x", header_get_magic(header), 'N', 'P', 'P', 'E');
      			return error; 
      		}
		}
    }
    while(search_finished);
    
    *pBase = base;
    *pStart = start; 
}

/*
procedure GoBackInSource_(w:Word);
  begin
    d1_Seek(d1_GetPos-w);
  end;

function InflateRead0:byte;far;
  var
    t:byte;
  begin
    if d1_GetPos(*+0*)=d1_laenge then
      t:=0
    else
      d1_Read(t,1);
    InflateRead0:=t;
  end;

function InflateRead4:byte;far;
  var
    t:byte;
  begin
    if d1_GetPos+4=d1_laenge then
      t:=0
    else
      d1_Read(t,1);
    InflateRead4:=t;
  end;


function End_of_Input0 : Boolean;
  begin
    End_of_Input0:=(d1_GetPos(*+0*)=d1_laenge);
  end;

function End_of_Input4 : Boolean;
  begin
    End_of_Input4:=(d1_GetPos+4=d1_laenge);
  end;

function InflateFlush_(w:Word):integer;far;
  begin
    with datei_tabelle^[dateizaehler] do
      begin
        if dateilaenge=0 then
          if SizeOf(anfang)>w then
            Move(slide^,anfang,w)
          else
            Move(slide^,anfang,SizeOf(anfang));
        Inc(dateilaenge,w);
        Write(' ]',(d1_GetPos/d1_laenge):6:3,#8#8#8#8','#8#8#8#8#8);
        Write(#8#8#8#8#8#8#8#8#8#8#8#8#8#8#8#8#8#8#8#8,d1_GetPos-archivstart:8,' -> ',dateilaenge:8);
      end;

    d2_Write(slide^,w);
    InflateFlush_:=0;
    UpdateCRC32(crc,slide^,w);
  end;



var
  l1,l2                 :longint;
  dll                   :string;
  dll_laenge            :longint;
  flags                 :longint;
  warten                :string;
  w1,w2                 :longint;
  fehler                :longint;
  zaehler,
  dateinummer_anweisungen:longint;

  quelldatei,
  zielverzeichnis       :string;

  bat,log               :text;
  datei_zeile           :string;
  verzeichnisanfang     :string;
*/

#warning implement external sources later
/*
procedure suche_informationsdatei;
  var
    w2                  :word;
    informationsdatei   :pBufStream;
  begin
    if dateinummer_anweisungen<>0 then
      Exit;

    (* Installationsanweisungen suchen *)
    WriteLn(textz_Suche_Datei_mit_den_Installationsanweisungen^);

    with datei_tabelle^[dateizaehler] do
      if (anfang[1]=$00) then
        begin

            for w2:=Low(anfang) to High(anfang)-20 do
              if (StrLComp(PChar(@anfang[w2]),#39'%s'#39    ,Length(#39'%s'#39    ))=0)
              or (StrLComp(PChar(@anfang[w2]),' %s '        ,Length(' %s '        ))=0)
              or (StrLComp(PChar(@anfang[w2]),' Install'    ,Length(' Install'    ))=0)
              or (StrLComp(PChar(@anfang[w2]),'Installation',Length('Installation'))=0)
               then
                begin
                  dateinummer_anweisungen:=dateizaehler;
                  Break;
                end;

          end;

    if dateinummer_anweisungen=0 then
      Exit;

    (* Daten laden *)
    informationslaenge:=datei_tabelle^[dateinummer_anweisungen].dateilaenge;
    GetMem(informationen,informationslaenge+$100);
    FillChar(informationen^,informationslaenge+$100,0);
    informationsdatei:=New(pBufStream,Init(zielverzeichnis+Pfadtrennzeichen+dname(dateinummer_anweisungen),stOpenRead,buffersize));
    obj_fehlerbehandlung(informationsdatei^.Status);
    informationsdatei^.Read(informationen^,informationslaenge);
    obj_fehlerbehandlung(informationsdatei^.Status);
    informationsdatei^.Done;
  end;


procedure verarbeite_patchformat;
  var
    kopierpuffer:pByteArray;
    schnittdatei:pBufStream;
    i           :longint;
    korrekt     :boolean;

  begin

    with datei_tabelle^[dateizaehler] do
      dateilaenge_2:=dateilaenge;

    with datei_tabelle^[dateizaehler] do
      if  (dateilaenge>=16)
      and (anfang[0] in [1..150]) then
        begin
          (* Patchkopf+vollstndige Datei *)
          if  (Plongint(@anfang[9])^+anfang[0]*12+13=dateilaenge)
          and (Plongint(@anfang[$d])^=0) then
            begin
              Write(textz_patchformat_vollstaendig^);
              dateilaenge:=Plongint(@anfang[9])^;
              dateilaenge_2:=dateilaenge;
              GetMem(kopierpuffer,dateilaenge);
              schnittdatei:=New(pBufStream,Init(zielverzeichnis+Pfadtrennzeichen+dname(dateizaehler),stOpen,buffersize));
              obj_fehlerbehandlung(schnittdatei^.Status);
              schnittdatei^.Seek(anfang[0]*12+13);
              obj_fehlerbehandlung(schnittdatei^.Status);
              schnittdatei^.Read(kopierpuffer^,dateilaenge);
              obj_fehlerbehandlung(schnittdatei^.Status);
              schnittdatei^.Seek(0);
              obj_fehlerbehandlung(schnittdatei^.Status);
              schnittdatei^.Write(kopierpuffer^,dateilaenge);
              obj_fehlerbehandlung(schnittdatei^.Status);
              schnittdatei^.Truncate;
              obj_fehlerbehandlung(schnittdatei^.Status);
              schnittdatei^.Done;
              WriteLn;
            end
          else
          if (Plongint(@anfang[$d])^=anfang[0]*12+13) then
            begin
              korrekt:=true;
              for i:=2 to anfang[0] do
                if (i-1)*12+13+4<High(anfang) then
                  (* Dateiposition Patchteil *)
                  if (PLongint(@anfang[(i-2)*12+13])^>=PLongint(@anfang[(i-1)*12+13])^)
                  or (PLongint(@anfang[(i-1)*12+13])^>dateilaenge) then
                    begin
                      korrekt:=false;
                      Break;
                    end;
              if korrekt then
                begin
                  WriteLn(textz_patchformat_unvollstaendig^);
                  dateilaenge_2:=Plongint(@anfang[9])^;
                end;
            end;
        end;
  end;
*/

/*
procedure berechne_aktuelle_rechnugsnull;
  var
    w1                  :longint;
  begin
    if (dateinummer_anweisungen=0)
    or (not debugmodus) then Exit;

    with datei_tabelle^[dateizaehler] do
      for w1:=40 to informationslaenge do

        if  ((PLongint(@informationen^[w1])^=dateilaenge) or (PLongint(@informationen^[w1])^=dateilaenge_2))
        and (PLongint(@informationen^[w1-8])^-PLongint(@informationen^[w1-12])^=laenge_eingepackt)
         then
          begin
            rechnungs_null:=archivstart-PLongint(@informationen^[w1-12])^;
            rechnungs_null_bekannt:=true;
            Exit;
          end;


  end;


procedure rate_naechstes_blockende(const jetzige_position:longint);

  begin
    if (not rechnungs_null_bekannt)
    or (not debugmodus)
    or (dateinummer_anweisungen=0) then
      Exit;

    with datei_tabelle^[dateizaehler] do
      if bekannte_formate^[ausgewaehltes_format].kein_crc then
        begin

          for w1:=40 to informationslaenge do

            if (PLongint(@informationen^[w1])^=jetzige_position-rechnungs_null)
            and (PLongint(@informationen^[w1+4])^-PLongint(@informationen^[w1])^>=0)
            and (PLongint(@informationen^[w1+4])^+rechnungs_null<=archivende) then
              WriteLn('? $',Int2Hex(PLongint(@informationen^[w1])^+rechnungs_null,8),
                      '+',PLongint(@informationen^[w1+4])^-PLongint(@informationen^[w1])^,
                      ' (',PLongint(@informationen^[w1+12])^,
                      ') = $',Int2Hex(PLongint(@informationen^[w1+4])^+rechnungs_null,8));
        end
      else
        begin
          for w1:=40 to informationslaenge do

            if (PLongint(@informationen^[w1])^=jetzige_position-rechnungs_null)
            and (PLongint(@informationen^[w1+4])^-PLongint(@informationen^[w1])^>=4)
            and (PLongint(@informationen^[w1+4])^+rechnungs_null<=archivende) then
              WriteLn('? $',Int2Hex(PLongint(@informationen^[w1])^+rechnungs_null,8),
                      '+',PLongint(@informationen^[w1+4])^-PLongint(@informationen^[w1])^-4,
                      '+4 (',PLongint(@informationen^[w1+12])^,
                      ') = $',Int2Hex(PLongint(@informationen^[w1+4])^+rechnungs_null,8));
        end;

  end;
*/
/*
procedure lade_datenbank;
  var
    pfad,dateiname,erweiterung,
    cfg_dateiname               :string;
    cfg                         :text;
    zeichen                     :char;

  procedure Uberlies_Leerzeichen;
    begin
      repeat
        if EoLn(cfg) then RunError(99);
        Read(cfg,zeichen);
      until not (zeichen in [' ',#9]);
    end;

  begin
    WriteLn(textz_lade_Datenbank_der_bekannten_Formate^);
    FSplit(ParamStr(0),pfad,dateiname,erweiterung);
    {$IfDef Debug}
    cfg_dateiname:='F:\v\e_wise\e_wise.vk\e_wise.ini';
    {$Else}
    cfg_dateiname:=pfad+'e_wise.ini';
    {$EndIf}
    Assign(cfg,cfg_dateiname);
    {$I-}
    Reset(cfg);
    {$I+}
    if IOResult<>0 then
      begin
        WriteLn(textz_Formatdatenbank__kann_nicht_geoeffnet_werden_1^,cfg_dateiname,textz_Formatdatenbank__kann_nicht_geoeffnet_werden_2^);
        Halt(1);
      end;

    zahl_bekannte_formate:=0;
    while not Eof(cfg) do
      begin
        if EoLn(cfg) then
          begin
            ReadLn(cfg);
            Continue;
          end;

        Read(cfg,zeichen);
        if not (zeichen in ['N','P']) then
          begin
            ReadLn(cfg);
            Continue;
          end;

        Inc(zahl_bekannte_formate);
        if zahl_bekannte_formate>High(bekannte_formate^) then
          begin
            WriteLn(textz_Zu_viele_Formatdefinitionen^);
            Halt(1);
          end;
        ReAllocMem(bekannte_formate,zahl_bekannte_formate*SizeOf(bekannte_formate^[1]));
        with bekannte_formate^[zahl_bekannte_formate] do
          begin
            case zeichen of
              'N':exe_typ:=exe_ne;
              'P':exe_typ:=exe_pe;
            end;
            Read(cfg,zeichen);
            if zeichen<'E' then RunError(99);
            Read(cfg,exe_laenge);
            Uberlies_Leerzeichen;dll:=zeichen='+';
            Read(cfg,archivstart);
            Read(cfg,ae_pos);
            Uberlies_Leerzeichen;;init_text:=zeichen='+';
            Read(cfg,pos_dateiname);
            Read(cfg,l_code);
            Read(cfg,l_data);
            Uberlies_Leerzeichen;kein_crc:=zeichen='+';
            if not EoLn(cfg) then RunError(99);
            ReadLn(cfg);
          end; (* with bekannte_formate^[zahl_bekannte_formate] do *)
      end; (* while not Eof(cfg) *)

    Close(cfg);
    if zahl_bekannte_formate=0 then
      begin
        WriteLn(textz_keine_Eintraege_in_e_wise_cfg_gefunden^);
        Halt(1);
      end;
  end;
*/
static gchar* unpack_directory = NULL;
static gchar** files_to_extract = NULL;
static gchar** wise_archive = NULL;

static gboolean enable_debug(const gchar *option_name, const gchar* value, gpointer data, GError **error)
{
	return TRUE;
}

static GOptionEntry entries[] =
{
	{ "",                 '\0', 0,                          G_OPTION_ARG_FILENAME,       &wise_archive,     "Wise archive to unpack",   NULL},
	{ "unpack_directory", 'd',  G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_STRING,         &unpack_directory, "Place to unpack files to", NULL},
	{ "debug",            '\0', G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK,       enable_debug,      "Enable debug mode",        NULL},
	{ "files",            '\0', 0,                          G_OPTION_ARG_FILENAME_ARRAY, files_to_extract,  "Narrows files to debug",   NULL}, 
	{ NULL }
};


int main(int argc, char* argv[])
{
	g_set_application_name("unwise - wise unpacker");
	
	//get_format_options(argc, argv);
	
	GError* error = NULL;
	GOptionContext* context = g_option_context_new("CHANGEME!");
	g_option_context_set_help_enabled(context, TRUE);
	g_option_context_add_main_entries (context, entries, NULL);
	if(!g_option_context_parse (context, &argc, &argv, &error))
	{
		g_print ("option parsing failed: %s\n", error->message);
		g_error_free(error);
		return 1;
    }

	int input_fd = open(wise_archive, "r");
#warning error handling missing
	GIOChannel* input = g_io_channel_unix_new(input_fd);
/*
  d1:=New(pBufStream,Init(quelldatei,stOpenRead,buffersize));
  if d1^.Status<>stOK then
    begin
      WriteLn(quelldatei,' ?');
      Halt(255);
    end;

  d1_laenge:=d1^.GetSize;
  archivende:=d1_laenge;
*/
  
	g_print("Search for start");
/*
  Write(textz_Suche_Anfang^);
*/
	gint64 base = 0;
	gint64 start = 0;
	guint16 setup_code_bytes = 0;
	guint16 setup_data_bytes = 0;
	enum exe_type type;
	error = skip_to_data(input, &type, &base, &start, &setup_code_bytes, &setup_data_bytes);
/*
  springe_zu_den_daten;
*/
/*
  d1_Seek(datenbasis+datenstart);
*/
	GIOStatus status = g_io_channel_seek_position
	(
		input, base + start, G_SEEK_SET, &error
	);
/*
  WriteLn;
*/
/*
  ausgewaehltes_format:=0;
  for zaehler:=Low(bekannte_formate^) to {High(bekannte_formate)} zahl_bekannte_formate do
    if  (datenstart=bekannte_formate^[zaehler].exe_laenge)
    and (gefundene_exe=bekannte_formate^[zaehler].exe_typ)
    and ((bekannte_formate^[zaehler].l_code=setup_programmcode_laenge ) or (bekannte_formate^[zaehler].l_code=-1))
    and ((bekannte_formate^[zaehler].l_data=setup_programmdaten_laenge) or (bekannte_formate^[zaehler].l_data=-1))
     then
      begin
        ausgewaehltes_format:=zaehler;
        Break;
      end;

  if ausgewaehltes_format=0 then
    begin
      WriteLn(textz_unbekanntes_WISE_Version_Autor_benachrichtigen^);
      if datenbasis<>0 then
        WriteLn(textz_start_des_wise_setup_programmes^,Int2Hex(datenbasis,8));

      Write(textz_EXE_Typ^);
      case gefundene_exe of
        exe_unbekannt:  Write('?');
        exe_ne:         Write('NE');
        exe_pe:         Write('PE');
      end;

      WriteLn(textz_EXE_Laenge^,Int2Hex(datenstart,8),
              textz_codeseg_laenge^,Int2Hex(setup_programmcode_laenge,8));
      Halt(255);
    end;

  (* exwise.c sagt Zusatz-dll -Dateiname *)
  if bekannte_formate^[ausgewaehltes_format].dll then
    begin
      d1_Read(dll[0],1);
      Inc(datenstart);

      if dll<>'' then
        begin
          d1_Read(dll[1],Length(dll));
          Inc(datenstart,Length(dll));
          d1_Read(dll_laenge,SizeOf(dll_laenge));
          Inc(datenstart,SizeOf(dll_laenge));
          Writeln('DLL: ',dll,textz_dll_laenge^,Int2Hex(dll_laenge,8));
        end;
    end;


  if not bekannte_formate^[ausgewaehltes_format].kein_crc then (* nicht im Uralt-Format *)
    begin

      d1_Read(flags,SizeOf(flags));

      if (flags and $0100)<>0 then
        begin
          d1^.Done;
          Write(textz_bitte_Pk_Un_zip_benutzen^);
          Halt(255);
        end;
    end;

  with bekannte_formate^[ausgewaehltes_format] do
    begin
      if ae_pos>0 then
        begin
          d1_Seek(datenbasis+datenstart+ae_pos);
          d1_Read(archivende_geladen,SizeOf(archivende_geladen));
          if archivende_geladen<>0 then
            archivende:=archivende_geladen+datenbasis;
        end;

      d1_Seek(datenbasis+datenstart+archivstart);

      if init_text then
        begin
          d1_Read(warten[0],SizeOf(warten[0]));
          d1_Read(warten[1],Length(warten));

          repeat
            w1:=Pos(#0,warten);
            if w1=0 then break;
            WriteLn('  "',Copy(warten,1,w1-1),'"');
            Delete(warten,1,w1);
          until false;
        end;

    end;

  Getmem(slide,WSIZE);
  FillChar(slide^,WSIZE,0);

  InflateFlush:=InflateFlush_;

  if bekannte_formate^[ausgewaehltes_format].kein_crc then
    InflateRead :=InflateRead0
  else
    InflateRead :=InflateRead4;

  GoBackInSource := GoBackInSource_;

  if bekannte_formate^[ausgewaehltes_format].kein_crc then
    End_of_Input:=End_of_Input0
  else
    End_of_Input:=End_of_Input4;

  dateizaehler:=0;
  datei_tabelle:=nil;

  (*$I-*)
  MkDir(zielverzeichnis);
  (*$I+*)
  fehler:=IoResult; (* keine Behandlung *)

  dateinummer_anweisungen:=0;
  rechnungs_null_bekannt:=false;

  (* Hauptschleife des Entpackens *)
  WriteLn(textz_Entpacke_Dateien^);
  repeat (**)

    rate_naechstes_blockende(d1_GetPos);
    Write(Int2Hex(d1_GetPos,8));
    if debugmodus then
      begin
        Write(' $');
        ReadLn(neue_position_zk);
        if neue_position_zk<>'' then
          begin
            Insert('$',neue_position_zk,1);
            Val(neue_position_zk,neue_position,kontrolle);
            if kontrolle<>0 then RunError(kontrolle);
            if neue_position=0 then Break;
            d1_Seek(neue_position);
          end;
      end;

    d1_Read(gepackter_datei_anfang,SizeOf(gepackter_datei_anfang));
    d1_Seek(d1_GetPos-SizeOf(gepackter_datei_anfang));

    if  (gepackter_datei_anfang[0]=0)
    and (gepackter_datei_anfang[1]=0)
     then
      Break;

    Inc(dateizaehler);
    dateiname:=zielverzeichnis+Pfadtrennzeichen+dname(dateizaehler);
    ReallocMem(datei_tabelle,dateizaehler*SizeOf(datei_tabelle^[1]));
    FillChar(datei_tabelle^[dateizaehler],Sizeof(datei_tabelle^[dateizaehler]),0);
    datei_tabelle^[dateizaehler].archivstart:=d1_GetPos;



    (*WriteLn(Int2Hex(d1_GetPos,8),'/',Int2Hex(d1_laenge,8));*)
    Write(dateizaehler:(2+3),' ',dname(dateizaehler),' [         ->          ]',(d1_GetPos/d1_laenge):6:3,#8#8#8#8','#8#8#8#8#8);

    d2:=New(pBufStream,Init(dateiname,stCreate,buffersize));
    if d2^.Status<>stOK then
      begin
        Write(textz_Fehler_beim_Erstellen^);
        Halt(255);
      end;

    InitCRC32(crc);
    l1:=InflateRun;
    if l1<>0 then
      begin
        WriteLn('InflateRun=',l1);
        RunError(l1);
      end;

    if not bekannte_formate^[ausgewaehltes_format].kein_crc then
      begin

    l2:=FinalCRC32(crc);

    d1_Read(l1,4);
    if (l1<>l2) and ((l1 shr 8)=(l2 and $00ffffff)) then
      begin
        d1_Seek(d1_GetPos-3);
        d1_Read(l1,4);
      end;

    if (l1<>l2) and ((l2 shr 8)=(l1 and $00ffffff)) then
      begin
        d1_Seek(d1_GetPos-5);
        d1_Read(l1,4);
      end;

    if l1<>l2 then
      begin
        WriteLn(textz_Pruefsummenfehler^);
        if not debugmodus then
          Halt(255);
      end;

      end;

    d2^.Done;

    (*if kurzformat then
      Write(^m)
    else*)
      WriteLn;

    with datei_tabelle^[dateizaehler] do
      laenge_eingepackt:=d1_GetPos-archivstart;

    verarbeite_patchformat;
    suche_informationsdatei;
    berechne_aktuelle_rechnugsnull;

  until d1_GetPos>=archivende; (**)

  d1^.Done;

  if dateinummer_anweisungen=0 then
    begin
      WriteLn;
      WriteLn(textz_Datei_mit_den_Dateiinformationen_nicht_gefunden^);
      Halt(255);
    end;

  (*$IFDEF OS2*)
  dateiname:=Int2StrZ(0,8)+'.CMD';
  (*$ELSE*)
  dateiname:=Int2StrZ(0,8)+'.BAT';
  (*$ENDIF*)
  WriteLn(textz_Erzeuge^,dateiname,textz_mit_den_gefundenen_Dateinamen^);
  dateiname:=zielverzeichnis+Pfadtrennzeichen+dateiname;

  Assign(bat,dateiname);
  Rewrite(bat);
  WriteLn(bat,'@ECHO OFF');
  WriteLn(bat,'REM E_WISE * V.K.');
  WriteLn(bat,'REM ',textz_Quelle^,': ',quelldatei);
  WriteLn(bat);
  WriteLn(bat,'IF [%1]==[] DEL ',Int2StrZ(0,8),'.TXT');

  Assign(log,zielverzeichnis+Pfadtrennzeichen+Int2StrZ(0,8)+'.TXT');
  Rewrite(log);

  repeat
    dateinamen_erkannt:=false;
    rechnungs_null_bekannt:=false;

    for zaehler:=1 to dateizaehler do
      with datei_tabelle^[zaehler] do
        for w1:=40 to informationslaenge do

          if  ((PLongint(@informationen^[w1])^=dateilaenge) or (PLongint(@informationen^[w1])^=dateilaenge_2))
          and (PLongint(@informationen^[w1-8])^-PLongint(@informationen^[w1-12])^=laenge_eingepackt)
          and ((not rechnungs_null_bekannt) or (PLongint(@informationen^[w1-12])^+rechnungs_null=archivstart))
           then
            begin
              if not rechnungs_null_bekannt then
                begin
                  rechnungs_null:=archivstart-PLongint(@informationen^[w1-12])^;
                  rechnungs_null_bekannt:=true;
                end;

              dateiname:=StrPas(Pchar(@informationen^[w1+bekannte_formate^[ausgewaehltes_format].pos_dateiname]));
              if dateilaenge<>dateilaenge_2 then
                dateiname:=dateiname+'.Patch';

              zeit:=PWord(@informationen^[w1-4])^ shl 16
                   +PWord(@informationen^[w1-2])^;

              Assign(d3,zielverzeichnis+Pfadtrennzeichen+dname(zaehler));
              FileMode:=open_share_DenyReadWrite+open_access_WriteOnly;
              Reset(d3,1);
              SetFTime(d3,zeit);
              Close(d3);

              FillChar(informationen^[w1-12],12+bekannte_formate^[ausgewaehltes_format].pos_dateiname+Length(dateiname),0);

              dateinamen_erkannt:=true;
            end;

  until not dateinamen_erkannt;


  for zaehler:=1 to dateizaehler do
    with datei_tabelle^[zaehler] do
      begin
        if not kurzformat then
          Write('   ',dname(zaehler));

        WriteLn(bat);

        Write(log,dname(zaehler));

        w1:=PWord(@anfang[0])^;
        if (w1=$0004) or (w1=$0014) then
          datei_zeile:='Informationen'
        else if  (w1>100) and (w1<600)
             and (PWord(@anfang[2])^>100) and (PWord(@anfang[2])^<500)
             and (( ((w1+7) and (not 7)) shr 1) * PWord(@anfang[2])^ + PWord(@anfang[4])^ + 10 = dateilaenge)
         then
          datei_zeile:='Grafik       '
        else if (anfang[0]=Ord('M')) and (anfang[1]=Ord('Z')) then
          datei_zeile:='EXE/DLL      '
        else if (PLongint(@anfang)^=$8) then
          datei_zeile:='Dialog ( 8)  '
        else if (PLongint(@anfang)^=$a) then
          datei_zeile:='Dialog (10)  '
        else if (PLongint(@anfang)^=$10) then (* DEL_DEMO.EXE.10 *)
          datei_zeile:='Dialog (16)  '
        else
          datei_zeile:='?            ';

        if not kurzformat then
          Write(' (',datei_zeile,')');

        (*WriteLn(bat,'REM Dateityp:  ',datei_zeile);*)

        gefunden:=false;
        datei_zeile:=datei_tabelle^[zaehler].dateiname;

        if datei_zeile<>'' then
          begin
            (* Doppelte Namen ? *)
            for w2:=1 to dateizaehler do
              if w2<>zaehler then
                if datei_zeile=datei_tabelle^[w2].dateiname then
                  begin
                    datei_zeile:=datei_zeile+'.'+Int2Str(zaehler);
                    Break;
                  end;

            if not kurzformat then
              Write(' ',datei_zeile);

            Write(log,' ',datei_zeile);

            while Pos('%',datei_zeile)>0 do
              Delete(datei_zeile,Pos('%',datei_zeile),Length('%'));
            if datei_zeile='' then Break;
            WriteLn(bat,'ECHO ',textz_Dateiname^,': ',datei_zeile);

            (* 'MAINDIR\T2\TEST.EXE'

                -> 'MKDIR  MAINDIR'
                   'MKDIR  MAINDIR\T2'
                   'RENAME 00000007.EWI '
                   'MOVE TEST.EXE MAINDIR\T2' *)

            verzeichnisanfang:=datei_zeile;
            for w2:=2 to Length(verzeichnisanfang) do
              if verzeichnisanfang[w2] in ['\','/'] then
                begin
                  WriteLn(bat,'IF NOT EXIST ',leer_sicherung(Copy(verzeichnisanfang,1,w2-1)),'\. MKDIR ',leer_sicherung(Copy(verzeichnisanfang,1,w2-1)));
                  datei_zeile:=Copy(verzeichnisanfang,w2+1,255);
                end;

            WriteLn(bat,'RENAME ',dname(zaehler),' ',leer_sicherung(datei_zeile));
            Dec(verzeichnisanfang[0],Length(datei_zeile));
            if verzeichnisanfang<>'' then
              begin
                Dec(verzeichnisanfang[0]); (* MAINDIR\T2\ -> MAINDIR\T2 *)
                WriteLn(bat,'MOVE   ',leer_sicherung(datei_zeile),' ',leer_sicherung(verzeichnisanfang));
              end;

            gefunden:=true;
          end;


        if not gefunden then
          for w1:=40 to informationslaenge do
            if  (PLongint(@informationen^[w1])^=dateilaenge)
            and (StrComp(@informationen^[w1+4],'DISPLAY'#0)=0)
             then
              begin
                datei_zeile:=StrPas(Pchar(@informationen^[w1+$4+Length('DISPLAY'#0)]));
                if not kurzformat then
                  Write(' Display: ',datei_zeile);

                WriteLn(bat,'REM Display    ',datei_zeile);

                gefunden:=true;
                Break;
              end;

        if not gefunden then
          for w1:=40 to informationslaenge do
            if  (PLongint(@informationen^[w1])^=dateilaenge)
             then
              begin
                if not kurzformat then
                  Write(' $',Int2Hex(w1,8),' ?');

                WriteLn(bat,textz_REM_Dateilaenge_wird_benutzt_bei^,Int2Hex(w1,8));
              end;

        if datei_tabelle^[zaehler].dateiname='' then
          WriteLn(bat,'IF [%1]==[] DEL ',dname(zaehler));

        WriteLn(log);

        if not kurzformat then
          WriteLn;
      end;

  WriteLn(bat);
  WriteLn(bat,'REM');
  (* auf Wechselbaren Datentrۄgern fragt OS/2
    sonst nach dem Datentrger mit der BAT/CMD-Datei *)
  (*WriteLn(bat,'IF [%1]==[] DEL %0');*)
  Close(bat);
  Close(log);

  DisPose(informationen);
  DisPose(datei_tabelle);
end.
*/
}
