/* FileListFREQestor */

#include <stdio.h>

struct rec
{
	char *line;
	struct rec *next,*pred;
};

extern FILE *file,*infreq,*outfreq;
extern int banet,banode,bapoint;
extern struct rec frec,*lrec;
extern char dmlnam[];

#define	CLS	msg("\033[1;1f\033[2J\200");
#define SCRTAK	msg("\033[4;23r\200");*(int *)0177560=0;
#define	SCRFRE	msg("\033[1;24r\200");*(int *)0177560=0xFFFF;

static int flag;

static frmenu()
{
	char a[100],b[100];
	CLS;
	SCRTAK;
	sprintf(a,"2:%d/%d.%d",banet,banode,bapoint);
	sprintf(b,"��(C)�Miha�Gusew���FREQ to %16s������������������������������������",a);
	msg(b);
	msg("� FREQer, Up:�, Down:�, PgUp:�, PgDn:�, FREQ:F,<Enter> Exit:E,S Quit:^C,Q     �");
	msg("�������������������������������������������������������������������������������");
	gotoxy(1,24);
	msg("�������������������������������������������������������������������������������\200");
	gotoxy(1,4);
}

long fpta[400];		/* offset in file */
int fptn;		/* current number */

extern long (ftell)();
static struct rec *cur,*ra,*rb;
static int t;

freqselect()
{
	int i;
	char st[200];
	flag=0;
	fseek(file,0L,0);
	frec.next=0;
	frec.pred=0;
	lrec=(&frec);
	fpta[0]=0L;
	fptn=0;
	for(i=0;i<100;i++)
	{
		if(i==50) fpta[++fptn]=ftell(file);
		if(fgetss(st,200,file)==0) {ra->next=0;break;}
		ra=malloc(sizeof(struct rec));
		if(!ra)
		{
			printf("��� ������\n");
			SCRFRE;
			exit(1);
		}
		lrec->next=ra;
		ra->pred=lrec;
		ra->line=xstrdup(st);
		lrec=ra;
		ra->next=1;
	}
	if(!i)
	{
		printf("File is empty\n");
		exit(1);
	}
	(frec.next)->pred=0;
	frmenu();
	t=0;
	for(cur=frec.next;;)
	{
		show(cur);
		t++;
		cur=cur->next;
		if((t==20)||(cur==0)) break;
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
			if(tryup())
			{
				msg("\033M\200");
				if(t) t--;
				else show(cur);
			}
			break;
		case 'D':
			for(i=0;i<15;i++) if(tryup())
			{
				msg("\033M\200");
				if(t) t--;
				else show(cur);
			} else break;
			break;
		case 'B':
			if(trydown())
			{
				msg("\033D\200");
				if(t!=19) t++;
				else show(cur);
			}
			break;
		case 'C':
			for(i=0;i<15;i++) if(trydown())
			{
				msg("\033D\200");
				if(t!=19) t++;
				else show(cur);
			} else break;
			break;
		case 'f':
		case 'F':
		case '\15':
			makefreq(cur->line);
			break;
		case 'S':
		case 's':
		case 'E':
		case 'e':
			SCRFRE;CLS;
			if(flag)
			{
				for(;;)
				{
					i=getc(infreq);
					if(i==(-1)) break;
					putc(i,outfreq);
				}
				fclose(infreq);
				fclose(outfreq);
			}
			else
				fpurge(outfreq);
			exit();
			break;
		case '\3':
		case 'q':
		case 'Q':
			SCRFRE;CLS;
			fpurge(outfreq);
			exit(1);
			break;
	}
}


static trydown()
{
	int i;
	char st[200];
	if(cur->next==1)
	{
		fptn++;
		fpta[fptn]=ftell(file);
		lrec=cur;
		for(i=0;i<50;i++)
		{
			if(fgetss(st,200,file)==0) {lrec->next=0;break;}
			if(fptn)
			{
				rb=frec.next;
				frec.next=rb->next;
				(rb->next)->pred=1;
				mfree(rb->line);
				mfree(rb);
			}
			ra=malloc(sizeof(struct rec));
			if(!ra)
			{
				printf("��� ������\n");
				SCRFRE;
				exit(1);
			}
			lrec->next=ra;
			ra->pred=lrec;
			ra->line=xstrdup(st);
			ra->next=1;
			lrec=ra;
		}
		if(i==0) fptn--;
	}
	if(cur->next)
	{
		cur=cur->next;
		return 1;
	}
	return 0;
}


static tryup()
{
	int i;
	char st[200];
	if(cur->pred==1)
	{
		cur->pred=(&frec);
		fptn--;
		fseek(file,fpta[fptn-1],0);
		for(i=0;i<50;i++)
		{
			if(fpta[fptn-1]==ftell(file)) break;
			if(fgetss(st,200,file)==0) break;
			rb=lrec;
			lrec=lrec->pred;
			lrec->next=1;
			mfree(rb->line);
			mfree(rb);
			ra=malloc(sizeof(struct rec));
			if(!ra)
			{
				printf("��� ������\n");
				SCRFRE;
				exit(1);
			}
			rb=cur->pred;
			cur->pred=ra;
			rb->next=ra;
			ra->pred=rb;
			ra->next=cur;
			ra->line=xstrdup(st);
		}
		((frec.next)->pred)=((fptn==1)?0:1);
	}
	if(cur->pred)
	{
		cur=cur->pred;
		return 1;
	}
	return 0;
}


makefreq(a)
char *a;
{
	char b[40],*p;
	int i;
	if(!((*a>' ')&&(*a<0200))) return;
	for(p=b,i=0;i<29;i++)
	{
		if(!((*a>' ')&&(*a<0200)))
		{
			*p='\0';
			fprintf(outfreq,"r0 %s\n",b);
			flag++;
			return;
		}
		*p++=(*a++);
	}
}



xstrdup(a)
{
	char *p,*q;
	q=strdup(a);
	if(p=q)		/* '=' */
	{
		for(;*p;p++) if(*p=='\200') *p='�';
	}
	return q;
}

                                                     