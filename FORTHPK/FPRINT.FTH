: // begin gtbyte 12 = until ; immediate

decimal	75 constant maxheig	// ������������ ���������� ����� �� ��������
	70 constant maxwid	// ������������ ������ �������
	4  constant distant	// ���������� ����� ���������
octal

//
// variables
//
region page maxheig 2* maxwid * allot 20 allot		// work field
region npage 0 ,	// ����� ��������
region nstpage 0 ,	// ����� ��������� ��������
region toprint 1 ,	// =1 ���� ����� �� printer
region ppwait 1 ,	// =1 if query for next page
region flendp 0 ,	// eof

: help ." \033[H\033[J
�����������������������������������������������������������
� (c) MGS1992    **** ������ � ��� ������� ****           �
�����������������������������������������������������������
  �����  LINES        - ���������� ����� � �������� - " maxheig . ." 
  �����  WIDTH        - ������ ��������             - " maxwid  . ." 
  �����  DIST         - ���������� ����� ���������  - " distant . ." 
  �����  START        - ����� ��������� ��������    - " nstpage ? ." 
         WAIT         - ������ � ��������������     - " ppwait @ if ." ***" then ." 
         NOWAIT       - ������ ��� �������������    - " ppwait @ ifnot ." ***" then ." 
         MONITOR      - �������� ����� �� ������    - " toprint @ ifnot ." ***" then ." 
         PRINTER      - �������� ����� �� ��������  - " toprint @ if ." ***" then ." 
 ����������������������������������������������������������
         FPRINT DEV:FILE.EXT - ������� ��� ������          -
         HELP                - �������� ���� �����         -
         STOP                - ������ � �������            - 
 ����������������������������������������������������������
Command> " ;


//
// ������� ����
//
: open
	." ��� �����:\015\012"
	1 bl word &file error" ������������ ��� �����"
	1 &close drop
	1 &lookup error" �� ����������� ������� ����"
	1 here &buffer ;

//
// ������� ���� �� �����
//
: get	1 &getbyte dup ifnot 52 c@
	abort" ������ ������ �� �������� �����" then ;

//
// ������ ��������
//
: printpage 
	npage @ nstpage @ < ifnot
		toprint @ if lpctty ." \017\033M\033\0" then
		maxwid spaces npage @ . cr cr
		maxheig 0 do i maxwid * page +
			maxwid 0 do dup i + c@ emit loop
			distant spaces
			maxheig maxwid * +
			maxwid 0 do dup i + c@ emit loop drop cr
		loop
		toprint @ if 14 emit stdtty then
	then ;


//
// ���������� ��������
//
region iii 0 ,
: filpage
	{ begin get while >c crtn repeat flendp 1!
	." \012\012��������� ��������!!!" begin bl >c crtn again } =crtn
	iii 0! begin
		crtn select
		11 case	iii @ maxwid mod 10 mod 10 swap - ?dup ifnot 10 then
			0 do bl iii @ page + c! iii 1+! loop ecase
		15 case crtn drop
			iii @ dup maxwid mod - maxwid + iii @ over iii !
			do bl i page + c! loop ecase
	        selector iii @ page + c! iii 1+!
		eselect
	maxheig 2* maxwid * iii @ > not until ;


//
// request to print to user
//
: da ." �� " r> drop stt ;
: net ." ���" r> drop r> 2+ >r stt ;	// drop next word in command sequence
: querypage
	ppwait @ if ." \015\012�������� �����: " npage ? ."  ;��������? "
		clt begin ttyin select
			c" D case da ecase c" d case da ecase
			c" � case da ecase c" � case da ecase
			c" y case da ecase c" Y case da ecase
			c" � case da ecase c" � case da ecase
			c" n case net ecase c" N case net ecase
			c" � case net ecase c" � case net ecase
			3 case stt ." ������ ��������\015\012" abort ecase
		eselect again
	then ;


//
// ������� ����
//
: work
	begin
		filpage
		querypage
		printpage
		npage 1+!
	flendp @ until ." ������ ���������\015\012" help ;

//
// ��������� ������� ������������
//
: fprint open 1 npage ! flendp 0! work ; : FPRINT fprint ;

//
// ������� �� ������������
//
: start	nstpage ! help ; : START start ;
: lines to maxheig help ; : LINES lines ;
: width	to maxwid help ; : WIDTH width ;
: dist	to distant help ; : DIST dist ;
: monitor toprint 0! help ; : MONITOR monitor ;
: printer toprint 1! help ; : PRINTER printer ;
: wait ppwait 1! help ; : WAIT wait ;
: nowait ppwait 0! help ; : NOWAIT nowait ;
: HELP help ;

//
// ��������� �����
//
: setup help interpret ;
' setup entryptr !
decimal 10 to base0
.( Compiled.)
.( Last address:)
octal h ? cr
                                                                                                                                                                                                                                                                                                                                             