/* Event Editor */
#include <stdio.h>
int $$narg=1;	/* no prompt */
FILE *file;	/* input/output file */
char st[200];	/* for input strings */
char *dblk="hd7:event.dml";

struct rec			/* in memory record */
{
	char *line;
	int flag;
	int ctl;
	struct rec *next,*pred;
} frec,*lrec;


main()
{
	printf("(C) Miha Gusew. Event Editor.\n");
	file=fopen(dblk,"r");
	if(!file)
	{
		printf("�� ���� ����� ���� '%s'\n",dblk);
		exit(1);
	}
	loading();
	rclist();
}



/*  Load file in memory */
loading()
{
	struct rec *a;
	char *p;
	printf("����������� ���� '%s'\n",dblk);
	frec.next=0;
	frec.pred=0;
	lrec=(&frec);
	for(;;)
	{
		if(fgetss(st,200,file)==0) break;
		a=malloc(sizeof(struct rec));
		if(!a)
		{
			printf("�� ������� ������ ��� �������� ����� �����\n");
			exit(1);
		}
		lrec->next=a;
		a->pred=lrec;
		a->next=0;
		a->flag=0;
		a->line=strdup(st);
		a->ctl=0;
		p=a->line;
		if(*p==';') while(*(++p)==';');
		if(((p[0]=='c')&&(p[1]=='a')&&(p[2]=='l')&&(p[3]=='l'))||
		((p[0]=='p')&&(p[1]=='o')&&(p[2]=='l')&&(p[3]=='l')))
			a->ctl=1;
		lrec=a;
	}
	fclose(file);
}



strdup(ptr)
{
	int retcode;
	if(retcode=malloc(strlen(ptr)+1)) stos(ptr,retcode);
	return(retcode);
}



stos(a,b)
char *a,*b;
{
	for(;*b++=(*a++););
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
msg("� Event Editor, Up:�, Down:�, Select:�, Deselect:�, Save:S,<Enter>, Quit:^C,Q �");
msg("�������������������������������������������������������������������������������");
	gotoxy(1,24);
	msg("�� Please select events �������������������������������������������������������\200");
	gotoxy(1,4);
}


static show(cur)
struct rec *cur;
{
	char c;
	c=cur->flag?'*':' ';
	if(cur->ctl)
		sprintf(st,"\033W  %c %s\15\033W\200",c,cur->line);
	else
		sprintf(st,"\033W         %s\15\033W\200",cur->line);
	msg(st);
}


rclist()
{
	struct rec *cur;
	int t;

	if(&frec==lrec)
	{
		printf("File is empty.\n");
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
			if(cur->ctl)
			{
				cur->flag=1;
				show(cur);
			}
			break;
		case 'D':
			if(cur->ctl)
			{
				cur->flag=0;
				show(cur);
			}
			break;
		case 's':
		case 'S':
		case '\15':
			if(rcout())
			{
				SCRFRE;CLS;
				return 1;
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
	int ft,fc;
	file=fopen(dblk,"w");
	if(!file)
	{
		msg("\0337\200");	/* save position */
		gotoxy(1,24);
		msg("�� Fuck, I can't write file ���� <Press any key> ������������������������������\007\200");
		key();
		gotoxy(1,24);
		msg("�� Please select events �������������������������������������������������������\200");
		msg("\0338\200");	/* restore position */
		return 0;
	}
	ptr=(&frec);
	ft=0;
	while(ptr=ptr->next)
	{
		p=ptr->line;
		if(*p==';')	while(*(++p)==';');
		if((ptr->ctl)&&(ptr->flag))
			fprintf(file,"%s\n",p);
		else
			fprintf(file,";%s\n",p);
	}
	fclose(file);
	return 1;
}



key()
{
	while(!(*(int*)0177560));
	return *(int*)0177562;
}
                                                                                                       