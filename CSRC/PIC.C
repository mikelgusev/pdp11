#include "turbo.h"
#define	FILL(y,yy,x,xx,c) HBMOVE(ARNUM(w),(V_MOV|V_BYTE|V_CV),y,yy,x,xx,c,0,0);
#define	FILX(y,yy,x,xx,c) HBMOVE(ARNUM(w),(V_XOR|V_BYTE|V_CV),y,yy,x,xx,c,0,0);
#define	SHOW(y,yy,x,xx,b) HBMOVE(ARNUM(w),(V_MOV|V_BYTE|V_PV),y,yy,x,xx,b,0,0);
#define	XOR(y,yy,x,xx,b)  HBMOVE(ARNUM(w),(V_XOR|V_BYTE|V_PV),y,yy,x,xx,b,0,0);
#define	TAKE(y,yy,x,xx,b) HBMOVE(ARNUM(w),(V_MOV|V_BYTE|V_VP),y,yy,x,xx,b,0,0);
#define	WSTR(y,x,s) WPRINT(ARNUM(w),y,x,s);
#define	CURSOR	XOR(y,9,x,4,&curs);
static	int	ax=0,ay=0,x=0,y=0;
extern int curs;

main(argv,argc)
int argv;
char *argc[];
{
	if(argv==1)
	{
		if(yes_no("\7\17���� �� ������","\7\17������� �����?")==0)
			exit(0);
		printf("������� ��� �����\n");
	}
}


yes_no(str1,str2)
char	*str1,*str2;
{
	int retcode=0;
	WINDOW w;
	WINDEF(w,64,100,100,164,5,22,(VM41|PL0),(XMAS1|YMAS1));
	WINFILL(w,255);
	WPRINT(ARNUM(w),5,5,str1);
	WPRINT(ARNUM(w),20,5,str2);
	WPRINT(ARNUM(w),45,21,"\7\6YES");
	WPRINT(ARNUM(w),45,64,"\7\2NO");
	for(;;)
	{
		moving(w);
		if((y>=64 && y<64+8)&&
			((x>=40 && x<40+8 )||
				(x>=21 && x<= 21+12 && (retcode=1)))) break;
	}
	WINKILL(w);
	return(retcode);
}


moving(w)
WINDOW w;
{
	int xx,yy;
	CURSOR;
	while(1)
	{
		if(MOUSE)
		{
			CURSOR;
			x=(xx=MXX)*2+ax;y=(yy=MYY)*2+ay;
			if(x<0) ax-=x;
			if(y<0) ay-=y;
			if(x>w.ar[3]-10) ax-=x-w.ar[3]+10;
			if(y>w.ar[2]-4) ay-=y-w.ar[2]+4;
			x=xx*2+ax;y=yy*2+ay;
			CURSOR;
		}
		if(MLEFT||MRIGHT)
		{
			CURSOR;
			return (0);
		}
	}
}

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       