( ******* About ***********
	SIG sig_name
	H sig_name
	L sig_name
	sig_name ?
	DEL sig_name
	AND  In.sig Out.sig ... ;
	ANDN, OR, ORN, XOR, XORN
	GEN TAB sig1 ... OUTPUT sigK ... ;
	TAB
******************************* )

: ex<> over @ ['] exit <> ;
create ovex 17545 , 2 , 137 , ' execute ,
create s2 62765 , 2 , 2 , 134 ,
: end press 1 and ;
: endnot end 1 xor ;
: <&& compile [compile] <build compile ] [compile] does> ; immediate
: && [compile] begin compile ex<> [compile] while compile ovex ; immediate
: &&>  compile s2 [compile] repeat compile end    ; immediate
: &&>n compile s2 [compile] repeat compile endnot ; immediate

: AND	<&& -1 && and &&> ;
: ANDN	<&& -1 && and &&>n ;
: OR	<&&  0 && or  &&> ;
: ORN	<&&  0 && or  &&>n ;
: XOR	<&&  0 && xor &&> ;
: XORN	<&&  0 && xor &&>n ;
: TO [compile] to ;

: SIG 0 constant ;
: H 1 [compile] to ;
: L 0 [compile] to ;
: ? . ;
: DEL forget ;

: OUTPUT compile exit ; immediate

: (&&	[compile] begin
	{ dup @ dup ['] exit <> } ,
	[compile] while ; immediate
: &&)	[compile] repeat compile drop ; immediate
: clear	(&& 2+ 0! 2+ &&) drop ;
: succ
	1 >r 
	(&& 2+ dup @ r> + dup 2/ >r
	1 and swap ! 2+ &&) drop r>
;

: (prod) (&& execute . 2+ &&) ;
: prod	(prod) 2+ ."  -->" (prod) drop cr ;

: GEN
	<build ] does>
	dup clear
	begin
		dup prod
		dup succ
	until drop
;

( ********** Testing ************* )

SIG A
SIG B
SIG C
AND  X A B C ;
OR   Y A B ;
XOR  Z B C ;
ANDN W X Y Z ;
GEN TAB A B C OUTPUT X Y Z W ;
TAB
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           