
region table 1000 allot

: fill ( ������� �������������� ��������� ������� ������������� )
       400 0 do i dup 2* table + ! loop ;

fill

: c bl word c@ bl word c@ swap 2* table + ! ;

c j �
c c �
c u �
c k �
c e �
c n �
c g �
c { �
c } �
c z �
c h �
c f �
c y �
c w �
c a �
c p �
c r �
c o �
c l �
c d �
c v �
c | �
c q �
c ~ �
c s �
c m �
c i �
c t �
c x �
c b �
c ` �


: convbyte ( byte�byte ) ( ������������� ���� ��������� � ������ )
  2* table + @ ;
 

region buf1 1000 allot   ( ����� ��� �������� ����� )
region buf3 1000 allot   ( ����� ��� ��������� �����  )

: @@@

	3 c" = word &file
	1 bl word &file and error" ����.��� ������"

   1 &close drop
   3 &close drop

   1 &lookup error" �� ����������� 1-�� ����"
   3 &enter  error" �� ����������� ���. ����"

   1 buf1 &buffer
   3 buf3 &buffer

   begin
         1 &getbyte
   while
         convbyte
         3 &putbyte error" ������ ������ � ���. ����"
   repeat

   52 c@ abort" ������ ������ �� 1-�� �����"

   1 &close drop
   3 &close error" ������ �������� ��������� �����"
   ." ��� O'K" cr
;

: help ." (c) MGS 1992 *** DnLAT->UpRus case
@@@ output=input" cr ;
: HELP help ; : /H help ; : /? help ; : /h help ;

help
abort
                                                                                                                                                                                                                                                              