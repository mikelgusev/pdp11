: -- begin begin gtbyte 12 = until ; immediate
-- ������������������������������
-- � Requests for Window system �
-- ������������������������������
-- region for temporary counter in area
region _cnt_ 0 , 0 ,
-- let cnt:=value
create <cnt 11537 , _cnt_ , 12537 , _cnt_ 2+ , 134 ,
-- take old cnt value
create cnt> 13745 , _cnt_ 2+ , 134 ,
-- let (cnt)+:=value
create dw 13700 , _cnt_ , 12520 , 10037 , _cnt_ , 134 ,
-- letb (cnt)+:=value
create db 13700 , _cnt_ , 112520 , 10037 , _cnt_ , 134 ,
-- region for storing stack pointer
region _sp_ 0 ,
-- splay to words
create spl ( a,b-a:b) 116565 , 2 , 3 , 111565 , 2 , 5725 , 134 ,
-- store stack pointer
: <req sp@ _sp_ ! ;
-- request from memory
create req ( area- ) 12537 , 177530 , 240 , 134 ,
-- request from stack
: req> sp@ req _sp_ @ sp! ;
-- window system requests codes
0 constant _arinst
2 constant _arkill
4 constant _vwcre
6 constant _vwkill
10 constant _vwtake
12 constant _vwfore
14 constant _vwback
16 constant _plcre
20 constant _plfre
22 constant _plmod
24 constant _plsav
17 constant _plcrex
21 constant _plfrex
23 constant _plmodx
25 constant _plsavx
26 constant _crset
30 constant _crera
32 constant _fninst
34 constant _fnkill
36 constant _fnfind
40 constant _fnlook
42 constant _vwlook
44 constant _wprint
46 constant _arcre
50 constant _hbmove
200 constant v.mask
100 constant v.dx
040 constant v.dy
030 constant v.vp
020 constant v.vv
010 constant v.pv
000 constant v.cv
006 constant v.bic
004 constant v.bis
002 constant v.xor
000 constant v.mov
001 constant v.byte
0 constant vm1
1 constant vm2
2 constant vm40
3 constant vm41
7 constant vm8
000000 constant pl0
040000 constant pl1
100000 constant pl2
140000 constant pl3
000004 constant plb
-- ����������������
-- � VPO requests �
-- ����������������
create get4k ( n4k-a ) 12537 , 174176 , 240 , 10045 , 134 ,
create get8k ( n8k-a ) 12537 , 174200 , 240 , 10045 , 134 ,
create fre4k  ( n4k,a- ) 12500 , 12537 , 174174 , 240 , 134 ,
create fremem ( n8k,a- ) 12500 , 12537 , 174202 , 240 , 134 ,
create hlt! ( n,adr ) 12501 , 12500 , 10137 , 174216 , 240 , 134 ,
create hlt@ ( adr ) 12537 , 174220 , 240 , 10045 , 134 ,
-- ����������������������������
-- � Useful words for control �
-- ����������������������������
: crset ( x,y- ) swap _crset sp@ req drop drop drop ;
: crera ( ) _crera sp@ req drop ;
-- ����������������������������������
-- � Mouse registers & work with it �
-- ����������������������������������
-- coordinates of mouse
region mxx 0 ,
region myy 0 ,
region mcsr 0 ,
-- take flag of mouse ready
create mouse ( -?)
	5045 , 105737 , 176204 , 100012 , 5115 ,
	13737 , 176204 , mcsr ,
	13737 , 176200 , mxx ,
	13737 , 176202 , myy , 134 ,
-- ���������������������
-- � Work with windows �
-- ���������������������
-- region for temporary saving par & len of taking memory
region _tmem_ 0 , 0 ,
-- make tas & install area
create arinst ( area,lins,slen,vmpl-arnum)
	16501 , 6 , 12721 , _arinst , 5021 , 16521 , 4 , 16521 , 2 ,
	10137 , _cnt_ , 16545 , 4 , 4437 , ]
	10000 3 pick / /mod swap if 1+ then 1+ 2/ dup _tmem_ ! get8k
	dup lit [ _tmem_ 2+ , ] ! or 0
	3 pick 0 do
		dup dw over dw
		next [ 66515 , 4 , 32715 , 170000 , 1404 ,
		5015 , 62765 , 20 , 2 , 4437 , ]
	loop drop drop drop drop dup req 2+ @ ;
-- make window
: mkwin ( area,sy1,sy2,sx1,sx2,den,plmod-anum,vwnum)
	6 pick 26 + 5 pick 7 pick - 3  pick swab 3 and 2- << 4 +
	4 pick 6 pick - 1+ 10 * 4 pick           3 and 2- << 3 pick arinst
	press dup
	7 pick 4 + <cnt _vwcre dw 0 dw dw 0 dw 0 dw 5 pick dw 4 pick dw
	3 pick dw rot dw swap dw cnt> req
	press press press swap dup 6 + @ swap
	_tmem_ @ over ! _tmem_ 2+ @ swap 2+ ! ;
-- allocating memory for window descriptor
: wallot ( lins- ) 4 * 42 + allot ;
-- ������������������������������
-- � Palette working primitives �
-- ������������������������������
-- get palcode for i-th element
create getcol ( i,pal-code )
	12501 , 12702 , 40 , 16103 , 2 , 42703 , 7 ,
	22703 , 7 , 1002 , 12702 , 400 , 62701 , 4 ,
	62501 , 111145 , 60201 , 111145 , 134 , 
-- set palcode for i-th element
create setcol ( code,i,pal- )
	12501 , 12702 , 40 , 16103 , 2 , 42703 , 7 ,
	22703 , 7 , 1002 , 12702 , 400 , 62701 , 4 ,
	62501 , 116511 , 1 , 60201 , 111511 , 5725 , 134 , 
-- taking palette
: plsavx ( area,vmpl-) swap <cnt _plsavx dw dw cnt> req ;
-- modifying palette
: plmodx ( area,vmpl-) swap <cnt _plmodx dw dw cnt> req ;
-- palcode to 8-bit rgb
create pal>rgb ( pal-r,g,b )
	11500 ,
	10001 , 72271 , -5 , 42701 , 340 not , 10115 ,
	10001 ,              42701 , 30  not , 50115 ,
	10001 , 301 ,        42701 , 340 not , 10145 ,
	10001 , 72271 , -3 , 42701 , 34 not  , 50115 ,
	10001 , 72271 , -2 , 42701 , 300 not , 10145 ,
	10001 , 72271 ,  3 , 42701 , 70 not  , 50115 , 134 ,
-- 8-bit rgb to palcode
create rgb>pal ( r,g,b-pal )
	11500 , 72270 , -3 , 42700 ,      7 not , 10001 ,
	12500 , 72270 ,  2 , 42700 ,   1400 not , 50001 ,
	11500 , 72270 ,  3 , 42700 ,    340 not , 50001 ,
	12500 , 301 ,      , 42700 , 160000 not , 50001 ,
	11500 ,            , 42700 ,     30 not , 50001 ,
	11500 , 72270 ,  5 , 42700 ,  16000 not , 50001 , 10115 , 134 ,
-- �����������������������
-- � Make Overlay module �
-- �����������������������
putovr wdc.ovr --
.( VPO & WDC requests assembled into WDC.OVR )
stop
                                                                                                                                                                                                                   