
region buf 1000 allot

variable c
variable num
variable pag

: lput
	lpctty emit stdtty ;

: npag
	lpctty decimal
	32 spaces ." -" pag ? ."  -" cr cr
	stdtty octal ;

: @@@
	num 0!
[ decimal ]
	9 pag !
[ octal ]
	1 bl word &file error" Error file name"
	1 &lookup error" File not found"
	1 buf &buffer
	npag
	begin
	1 &getbyte
	while
	c !
	c @ 12 = if
		num 1+!
[ decimal ]
		num @ 48 = if
[ octal ]
			14 lput
			clt
			pag 1+!
			decimal ." Page" pag ? octal
			begin ttyin bl = until
			stt cr
			num 0!
			npag
		else
			15 lput
			12 lput
		then
	else
		c @ lput
	then
	repeat
	drop
	1 &close
;
                                                                                                                                                                                                                                                                                                                                                                                   