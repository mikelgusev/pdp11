octal

: -- begin gtbyte 12 = until ; immediate

-- �������� ����� ��� ������� ���������� �������� ������ �����.
-- ���� � ���, ��� ����� �����, ��� dump,getovr,putovr,(bug)
-- line,crtn,mark,label ������� �������� � ������������ �� �����
-- � ����� ����������� � ����� ����� �� ����ް��������� � ����������
-- ��������� ������ ��������������� � �������� �����.

-- ��������������� �������� ��������� � ����� (bug), �������
-- �� ������ �������� � ����� ����� ����� ���������. ��� ���
-- ������ �� ����� ��������� �������������� ���� � ���������,
-- ������ ������, ��� ���������� ����� ��� �������� �� �����
-- ���������� � ������� ������� �������, � ���-�� ���-�� �����
-- ���������. ����� ����� ������������ �� ��������� �����
-- ��������� ��������� ��������:
-- "I" - ������� �������������. ��� ����� ������ ��������,
	-- �.�. �� ������ ��������� ����� ��������,
	-- ����� ���������� ���� ���������, � �����
	-- ����� ����� � ������������ ��������� �� �������
	-- "exit" ����������� � ������ ����������������� ����������
-- "N" - ������ �� ��������������� � ������ ����� ��������
-- "Q" - ������ �� ��������������� � ����� ������ ��������
-- "R" - ���������� � �������
-- "S" - ������� �� ����� ���������� �����
-- "V" - ��������� ������� vlist, �.�. ���������� ������� �����


-- ����� ���������� ����� "bugon" ����� ��������, t.e.(bug), �����
-- ���������� ����� ������� ����������� ����� ����� ����� ":"

-- �������������� ����� "bugof" ��� �������� �� ���� �����.
-- �� ������������ ����� �������� �� �������, ��� ���������
-- ������ �� ����������, ����� ������� �� ������ ����������
-- ������� ���������, ��� ��� ���������� ��������� ������
-- �� ����� ������� �� �� ������������.


-- ����� ���� ���������� ������ ��������� �� �����.
-- ��� ��� ������, ��� � ����� ����� ������ �� ���������� �����,
-- �.�. ����� ���� � �������� �����, � � �������������
-- �������������� ������, �.�. ���� ����� �� ����� ��� �������
-- ����� ��� ��������� ��������� ���������� �� � �������� �����.


-- ������ �����, ������� ������ �� ������
create (empty) 134 ,

-- ��������� ��������� ���������� �����
: (getpar)
	>r
	base @ 		( base )
	iodir @ 	( base,iodir )
	ttycsr 		( base,iodir,ttycsr )
	ttydat 		( base,iodir,ttycsr,ttydat )
	177560 @ 	( base,iodir,ttycsr,ttydat,ktrap )
	r>		( base,iodir,ttycsr,ttydat,ktrap,name )
;

-- ���������� ��������� ��� ��������� ���������
: (setpar)
	10 base !
	iodir 0!
	stdtty
	177560 0!
;

-- ������������ ���������(����� ������) ���������� �����
: (putpar)
	drop
	177560 !
	to ttydat
	to ttycsr
	iodir !
	base !
;

-- ���������� ��� ��������, ��������� ����� �����, ��� ����������
: (debug)
	last @ next [
	21504 ,
	103410 ,
	11500 ,
	105720 ,
	1376 ,
	5200 ,
	6200 ,
	6300 ,
	11015 ,
	765 ,
	4437 ,
]	dup error" ������������ �����"
	(getpar)
	begin
	(setpar)
	cr ." �����: "
	dup type
	cr ." (I)nterpret,(N)o,(Q)uit,(R)t,(S)tack,(V)list ? "
	begin 177560 @ 200 and until 177562 c@
	dup c" A > if 177737 and then
	dup emit cr
	select
	15 case (putpar) exit ecase
	c" I case
	>r >r >r >r >r >r
	-1 177560 !
	interpret
	r> r> r> r> r> r>
	ecase
	c" N case ['] (empty) r@ 2- ! (putpar) exit ecase
	c" Q case 134 ['] (debug) ! (putpar) exit ecase
	c" R case -1 177560 ! stop ecase
	c" S case >r >r >r >r >r >r s. r> r> r> r> r> r> ecase
	c" V case vlist ecase
	eselect
	again
;


-- ��������������� ����� ���������, �� ���������� ���������
-- ��� ����� ������ ����������� ��� ������ bugon � bugof
: : smudge [compile] : compile (debug) smudge ; immediate

-- ����� ������� ��������� � ���, ��� �����  smudge �����������
-- ������������, ��� �������� �� �������� ����������� �����������:
-- ��������: �������� ������ ����� �� ������
-- �������� ��� ���: ������� ������ ����� � �����
-- ��������: �������� ������ ����� �� ������
-- �������� ��� ���: ������� ������ ����� � �����
-- . . . . .

                                                                                                                                               