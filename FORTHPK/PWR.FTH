: // begin gtbyte 12 = until ; immediate
region buf 1000 allot
// FSC-0045
// unsigned int onode,dnode,opoint,dpoint;
0 constant onode
2 constant dnode
4 constant opoint
6 constant dpoint
// char zeros[8];
10 constant zeros
// unsigned int subver,version,onet,dnet;
20 constant subver
22 constant version
24 constant onet
26 constant dnet
// char product,rev_lev,password[8];
30 constant product
31 constant rev_lev
32 constant password
// unsigned int ozone,dzone;
42 constant ozone
44 constant dzone
// char odomain[8],ddomain[8];
46 constant odomain
56 constant ddomain
// long specific;
66 constant specific
72 constant NEWPKT

region pn NEWPKT allot

: attrstr
	drop " ATTR"
;

: n	word r= number ifnot ." Illegal Number" r> type stop else rdrop
	drop drop ;

: OA:	c" : n pn ozone  + !
	c" / n pn onet   + !
	c" . n pn onode  + !
	c" @ n pn opoint + ! 
	n pn odomain
	 bl word dup 10 + swap do i c@ ifnot leave then i c@ over c! 1+ loop
;


: DA:	c" : n pn dzone  + !
	c" / n pn dnet   + !
	c" . n pn dnode  + !
	c" @ n pn dpoint + ! 
	n pn ddomain
	 bl word dup 10 + swap do i c@ ifnot leave then i c@ over c! 1+ loop
;


: main
	." (C) Miha Gusew 1994 PKT-maker\015\012"
	2 pn subver + !
	2 pn version + !
	0 pn product + !
	0 10 pn password + cfill
;


2
mh typedef struct {
    unsigned int xonode,xdnode,xonet,xdnet,xattr;
    int          xcost;
} MSGHDR;
(
	from xonet/xonode to xdnet/xdnode
	xattr
)
date:	19
to:	36
from:	36
subj:	72
until zero


: start
	1 &enter error" bad enter"
	1 buf &buffer
;


: PKT:
	1 bl word &file ifnot ." Bad file name" stop then
	1 &enter ifnot ." Bad enter PKT file" stop then
	1 buf &buffer decimal
;



                                                                                                                                                                                                                                                                                                              