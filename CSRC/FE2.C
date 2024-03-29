/* ArcViewer library */
/* int patmat(char *raw,char *pat); */
/* char *trim(char *name); */

patmat(raw,pat)
char *raw,*pat;
{
	int  i ;
	if(*pat=='\0') return (*raw=='\0');
	if(*pat=='*')
	{
		if(*(pat+1)=='\0')	return( 1 ) ;
		for(i=0;i<=strlen(raw);i++)
			if((*(raw+i)==*(pat+1)) ||
			 (*(pat+1)=='?') || (*(pat+1)=='%'))
				if(patmat(raw+i+1,pat+2) == 1) return(1);
	}
	else
	{
		if(*raw=='\0') return 0;
		if((*pat=='%')||(*pat=='?')||(*pat == *raw))
			if(patmat(raw+1,pat+1)==1) return 1;
	}
	return 0;
}

static char name[100];
char *trim(str)
char *str;
{
	char *p;
	for(p=name;*str;str++) if((*p=(*str))!=' ') p++;
	*p='\0';
	return name;
}


                                                                                                                                                                                                                                                                                                                                          