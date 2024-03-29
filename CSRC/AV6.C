/* ArcViewer Library */
#include <stdio.h>

extern of;
static char s[100];
extern char *arc[];
static int space=0;
static char *aptr;


struct rec
{
	char *anm;
	char *fnm;
	char tar;
	char flg;
	struct rec *next;
	struct rec *pred;
} frec,*lrec;


rcopen()
{
	frec.next=0;
	frec.pred=0;
	lrec=(&frec);
}


rcarchive(ptr)
{
	if(space) return;
	aptr=strdup(ptr);
	if(!aptr) space++;
}


rcfile(ptr,at)
{
	struct rec *a;
	char *fptr;
	if(space) return;
	a=malloc(sizeof(struct rec));
	if(!a) {space++;return;}
	fptr=strdup(ptr);
	if(!fptr) {space++;return;}
	lrec->next=a;
	a->pred=lrec;
	a->next=0;
	lrec=a;
	a->anm=aptr;
	a->fnm=fptr;
	a->tar=at;
	a->flg=0;
}


strdup(ptr)
{
	int retcode;
	if(retcode=malloc(strlen(ptr)+1)) stos(ptr,retcode);
	return(retcode);
}


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
msg("� ArcViewer, Up:�, Down:�, Select:�, Deselect:�, Extract:E,<Enter>, Abort:^C,Q�");
msg("�������������������������������������������������������������������������������");
	gotoxy(1,24);
if(space)
	msg("�� No memory for storing all filenames ����������������������������������������\200");
else
	msg("�������������������������������������������������������������������������������\200");
	gotoxy(1,4);
}


static show(cur)
struct rec *cur;
{
	char c;
	c=cur->flg?'*':' ';
	sprintf(s,"\033W   %c %-16s %c %s\15\033W\200",c,cur->anm,c,cur->fnm);
	msg(s);
}


rclist()
{
	struct rec *cur;
	int t;

	if(&frec==lrec)
	{
		printf("No files\n");
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
		case 'C':
			cur->flg=1;
			show(cur);
			break;
		case 'D':
			cur->flg=0;
			show(cur);
			break;
		case 'e':
		case 'E':
		case '\15':
			rcout();
			SCRFRE;CLS;
			return 1;
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
	while(ptr=ptr->next)
		if((ptr->flg)&&(ptr->tar>=1)&&(ptr->tar<=4))
		{
			if(ptr->tar==4)
			{
				fprintf(of,"%s %s=%s",arc[ptr->tar-1],ptr->fnm,ptr->anm);
			}
			else
			{
				for(p=ptr->fnm;*p;p++) if(*p=='/') *p='\\';
				fprintf(of,"%s %s,%s",arc[ptr->tar-1],ptr->anm,ptr->fnm);
			}
			inskey(ptr->tar);
			fprintf(of,"\n");
		}
}

key()
{
	while(!(*(int*)0177560));
	return *(int*)0177562;
}
                                                                                                                                                                                                                                                                                                                                                                                          