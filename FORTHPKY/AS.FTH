: .. -- begin gtbyte 12 = until ; immediate

.. ���������� ���������, ������� �� ������ ����������
.. � ������ ��������� ��������������� � ��������
.. ������ ��� ����� �� ���������� ��������� ���
.. ������������ � ������.

: c> constant ;
005000 c> .clr	105000 c> .clrb	005100 c> .com	105100 c> .comb
005200 c> .inc	105200 c> .incb	005300 c> .dec	105300 c> .decb
005400 c> .neg	105400 c> .negb	005500 c> .adc	105500 c> .adcb
005600 c> .sbc	105600 c> .sbcb	005700 c> .tst	105700 c> .tstb
006000 c> .ror	106000 c> .rorb	006100 c> .rol	106100 c> .rolb
006200 c> .asr	106200 c> .asrb	006300 c> .asl	106300 c> .aslb
006700 c> .sxt	000300 c> .swab	000100 c> .jmp	004700 c> .call
000200 c> .rts	106400 c> .mtps	106700 c> .mfps	010000 c> .mov
110000 c> .movb	020000 c> .cmp	120000 c> .cmpb	030000 c> .bit
130000 c> .bitb	040000 c> .bic	140000 c> .bicb	050000 c> .bis
150000 c> .bisb	060000 c> .add	160000 c> .sub	070000 c> .mul
071000 c> .div	074000 c> .xor	004000 c> .jsr	072000 c> .ash
073000 c> .ashc	000207 c> .return
000003 c> .bpt	000004 c> .iot	000002 c> .rti	000006 c> .rtt
000000 c> .halt	000001 c> .wait	000005 c> .reset
000241 c> .clc	000242 c> .clv	000244 c> .clz	000250 c> .cln
000257 c> .ccc	000261 c> .sec	000262 c> .sev	000264 c> .sez
000270 c> .sen	000277 c> .scc	000240 c> .nop	104000 c> .emt
104400 c> .trap	077000 c> .sob	000134 c> .nex	004437 c> .pcode
000400 c> .br	002000 c> .bge	002400 c> .blt	003000 c> .bgt
003400 c> .ble	101000 c> .bhi	101400 c> .blos	102000 c> .bvc
102400 c> .bvs	103000 c> .bcc	103000 c> .bhis	103400 c> .blo
103400 c> .bcs	001400 c> .beq	100000 c> .bpl	100400 c> .bmi
001000 c> .bne

: .mark. here ;
: <sob here swap - 2/ 77 and here 2- +! ;
: <res here 2+ - 2/ 377 and + ;
: res> here over - 2- 2/ swap +! ;

create test
	.mov 2700 + , 10 ,
.mark.
	.mov 0045 + ,
	.sob , <sob

	4437 ] . . . . . . . . next [

	.br	<res ,

	0 , 0 , 0 ,

.mark.	134	
	


                                                                                                      