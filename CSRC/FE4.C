/* File List EDitor Library */

struct rec
{
	char *line;
	struct rec *next,*pred;
};

extern struct rec frec,*lrec;

#define	CLS	msg("\033[1;1f\033[2J\200");
#define SCRTAK	msg("\033[4;23r\200");*(int *)0177560=0;
#define	SCRFRE	msg("\033[1;24r\200");*(int *)0177560=0xFFFF;



gotoxy(x,y)
{
	char s[30];
	sprintf(s,"\033[%d,%df\200\0",y,x);
	msg(s);
}



static rcmenu()
{
	CLS;
	SCRTAK;
msg("��(C)�Miha�Gusew���������������������������������������������������������������");
msg("� FileListSelector, Up:�, Down:�, Show:<Enter>, Quit:^C,Q                     �");
msg("�������������������������������������������������������������������������������");
	gotoxy(1,24);
	msg("�������������������������������������������������������������������������������\200");
	gotoxy(1,4);
}


show(cur)
struct rec *cur;
{
	char st[100],*p,*q;
	int i;
	p=st;
	q=cur->line;
	*p++='\033';
	*p++='W';
	*p++=' ';
	for(i=0;(i<80)&&(*q);i++) *p++=(*q++);
	*p++='\15';
	*p++='\033';
	*p++='W';
	*p++='\200';
	*p++='\0';
	msg(st);
}


rclist()
{
	struct rec *cur;
	int t;

	if(&frec==lrec)
	{
		printf("No files.\n");
		return 0;
	}
	rcmenu();
	t=0;
	for(cur=frec.next;;)
	{
		show(cur);
		t++;
		cur=cur->next;
		if((t==20)||cur==0) break;
		msg("\0");
	}
	gotoxy(1,4);
	cur=frec.next;
	t=0;
	for(;;) switch(key())
	{
		case 033:
		case '[': break;
		case 'A':
			if(cur->pred!=(&frec))
			{
				msg("\033M\200");
				cur=cur->pred;
				if(t) t--;
				else
					show(cur);
			}
			break;
		case 'B':
			if(cur->next)
			{
				cur=cur->next;
				msg("\033D\200");
				if(t!=19) t++;
				else
					show(cur);
			}
			break;
		case 's':
		case 'S':
		case '\15':
			if(rcout())
			{
				SCRFRE;CLS;
				return (cur->line);
			}
			break;
		case '\3':
		case 'q':
		case 'Q':
			SCRFRE;CLS;
			return 0;
			break;
	}
}


static rcout()
{
	struct rec *ptr;
	char *p;
	ptr=(&frec);
	while(ptr=ptr->next);
	return 1;
}



key()
{
	while(!(*(int*)0177560));
	return *(int*)0177562;
}
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 