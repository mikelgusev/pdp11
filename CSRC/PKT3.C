/* ArcViewer library 				*/
/* 		stos(char *src,*dst);		*/
/* 		dvOpen(); 			*/
/* 	char 	*dvNext(); 			*/
/*		patnam(char *d,*f,*src);	*/

#include	<ctype.h>

stos(a,b)
char *a,*b;
{
	for(;*b++=(*a++););
}

ustos(a,b)
char *a,*b;
{
	for(;*b++=toupper(*a++););
}

static int state;
static char dname[10];

dvOpen(dn)
char *dn;
{
	state=0;
	if(*dn=='*') dn="DK*";
	stos(dn,dname);
	if(*dn=='\0') {stos("DK",dname);return;}
	if(((dn[2]>='0')&&(dn[2]<='7'))||(dn[2]!='*')) return;
	state='0';
}

char *dvNext()
{
	if(state=='8') return 0;
	if(state==0) { state='8';return(dname);}
	dname[2]=state++;
	return(dname);
}

parnam(d,f,s)
char *d,*f,*s;
{
	char *p;
	int fld=0,fldd=0;
	for(p=s;*p;p++) if(*p=='.')fld++;else if(*p==':')fldd++;
	if(fldd)
	{
		for(p=s;*p!=':';*d++=(*p++));
		*d='\0';
		p++;
		if(*p=='\0') { stos("*.PKT",f);return;}
	}
	else
	{
		stos("DK",d);p=s;
	}
	if(*p=='.') *f++='*';
	do{*f++=_toupper(*p);}while(*p++);
	if(fld==0) { *(f-1)='.';*f++='P';*f++='K';*f++='T';*f='\0';}
}
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            