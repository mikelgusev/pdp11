: -- begin gtbyte 12 = until ; immedate


-- 	���������� ���������� �����, �� ����� � ����� ���������
--	� ������� ����� (� ������ ���������, �������)
variable x	-- ���������� ���. �����
variable y		--
variable x2	-- ���������� �������� �����
variable y2		--
variable dx	-- ������� �������� �����
variable dy		--
variable sx	-- ����� ���������� � �����������
variable sy		--
variable color	-- ���� ����� 0..3
variable e	-- ����������� � ���������
variable sw		-- ����������

-- �������� �����
: line color ! y2 ! x2 ! y ! x !
x2 @ x @ - dup abs dx ! dup if 0< if -1 else 1 then then sx !
y2 @ y @ - dup abs dy ! dup if 0< if -1 else 1 then then sy !
dy @ dx @ > if dx @ dy @ dx ! dy ! sw 1! else sw 0! then
dy @ 2* dx @ - e ! dx @ 0 do x @ y @ color @ pset
begin e @ 0< not while sw @ if sx @ x +! else sy @ y +! then
dx @ 2* e -! repeat
sw @ ifnot sx @ x +! else sy @ y +! then
dy @ 2* e +! loop ;

-- �������� ��� ������
: ttt 0 do 1200 rnd 330 rnd 1200 rnd 330 rnd 3 rnd line loop ;
	
     