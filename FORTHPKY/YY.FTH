: // begin gtbyte 12 = until ; immediate
// ************************
//
// Prefix notation if FORTH
//
// ************************
: PROC	[compile] : ;
: ENDP	compile next 207 , [compile] [ ; immediate
create GET	10446 , 16604 , 2 , 4734 , 10466 , 2 , 12604 , 134 ,
create PREFIX	4734 , 134 ,
create SEQ	4734 , 776 ,
create ENDS	5726 , 134 ,
create (LIT)	12445 , 207 ,
: LIT	?comp bl word number drop drop compile (LIT) , ; immediate
: one	PROC compile GET ' , [compile] ENDP ;
: par	PROC compile GET compile GET ' , [compile] ENDP ;
par	PLUS	+
par	MINUS	-
par	MUL	*
par	DIV	/
par	MOD	mod
one	PUTINT	.

: test	." must be 3 = "
	PREFIX PLUS LIT 1 LIT 2 .
	cr
	SEQ PUTINT PLUS LIT 1 MUL LIT 2 LIT 3
	    PUTINT LIT 3
	ENDS
;

.( Compilation complete)
                                                                                                                                                                                                                                                   