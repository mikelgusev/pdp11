#include "turbo.h"
#define	FILL(y,yy,x,xx,c) HBMOVE(ARNUM(w),(V_MOV|V_BYTE|V_CV),y,yy,x,xx,c,0,0);
#define	FILX(y,yy,x,xx,c) HBMOVE(ARNUM(w),(V_XOR|V_BYTE|V_CV),y,yy,x,xx,c,0,0);
#define	SHOW(y,yy,x,xx,b) HBMOVE(ARNUM(w),(V_MOV|V_BYTE|V_PV),y,yy,x,xx,b,0,0);
#define	XOR(y,yy,x,xx,b)  HBMOVE(ARNUM(w),(V_XOR|V_BYTE|V_PV),y,yy,x,xx,b,0,0);
#define	TAKE(y,yy,x,xx,b) HBMOVE(ARNUM(w),(V_MOV|V_BYTE|V_VP),y,yy,x,xx,b,0,0);
#define	WSTR(y,x,s) WPRINT(ARNUM(w),y,x,s);
#define	CURSOR	XOR(y,9,x,4,&curs);
/* no prompt */
$$narg=1;

/* external pictures */
extern int curs,k11,k1,pal,k21,k2,k31,k3,k4,k41,k5,k51,bord;

/* work window */
WINDOW	w;

/* offset for 0..3 directions */
static int dirx[8]={1,1,-1,-1};
static int diry[8]={1,-1,-1,1};

/* starting directions */
static int ds[5]={0,1,2,3,0};

/* starting coordinates */
static int xg[5]={10,30,50,70,90};
static int yg[5]={10,30,50,70,90};

/* backing to the start */
static int start[6];


/* mouse coordinates */
static int x,y;


/* handle mouse events */
mkey()
{
	if(MLEFT && INRECT(y,x,138,22,120,13)){
		CURSOR;SHOW(137,25,119,14,&k51);CURSOR;
		while(MLEFT);
		CURSOR;SHOW(137,25,119,14,&k5);CURSOR;
		exit(1);
	}
	if(MLEFT && INRECT(y,x,138,22,16,13)){
		CURSOR;SHOW(137,25,15,14,&k11);CURSOR;
		while(MLEFT);
		WINFILL(w,0252);
		FILL(4,192,2,152,0);
		gad();
	}
	if(MLEFT && INRECT(y,x,138,22,42,13)){
		CURSOR;SHOW(137,25,41,14,&k21);CURSOR;
		while(MLEFT);
		CURSOR;SHOW(137,25,41,14,&k2);CURSOR;
	}
	if(MLEFT && INRECT(y,x,138,22,68,13)){
		CURSOR;SHOW(137,25,67,14,&k31);CURSOR;
		while(MLEFT);
		CURSOR;SHOW(137,25,67,14,&k3);CURSOR;
	}
	if(MLEFT && INRECT(y,x,138,22,94,13)){
		CURSOR;SHOW(137,25,93,14,&k41);CURSOR;
		while(MLEFT);
		CURSOR;SHOW(137,25,93,14,&k4);CURSOR;
	}
}


/* show gades */
gad()
{	int i,c,b,j,fsh=0,ctrlx,try,dir;
	while(!(MLEFT)) {
		for(j=0;j<5;j++) {
			try=0;
			do {
				if(try!=0) { ds[j]=(ds[j]+1)&3; }
				c=yg[j]+diry[ds[j]]*2;
				b=xg[j]+dirx[ds[j]];
				TAKE(c,2,b,1,(&ctrlx));
				if(ctrlx==0) break;
				if(try==0) { ds[j]=(ds[j]+2)&3; }
			} while(try++!=4);
			if(ctrlx==0) {
				if(fsh!=0) { FILX(yg[j],2,xg[j],1,0167); }
				yg[j]=c;
				xg[j]=b;
				FILX(c,2,b,1,0167);
			}
		}
		fsh=1;
		for(i=1;i<512;i++);
	}
	longjmp(start,0);
}


/* Calling after using exit(1); */
wrapup()
{
	WINFILL(w,0252);
	FILL(4,192,2,152,0);
	WSTR(90,60,"\7\17GAME OVER");
	while(!(MLEFT||MRIGHT));
	WINKILL(w);
}


/* Main module */
main()
{	int xx,yy,ax=0,ay=0;
	MCSR = 040;
	WINDEF(w,200,160,50,250,2,22,(VM41|PL0),(XMAS1|YMAS1));
	setjmp(start);
	WINFILL(w,0252);	FILL(4,192,2,152,0);
	SHOW(137,25,15,14,&k1);	SHOW(167,20,9,24,&bord);
	WSTR(172,12,"\7\17GAME");
	SHOW(137,25,41,14,&k2);	SHOW(167,20,35,24,&bord);
	SHOW(137,25,67,14,&k3);	SHOW(167,20,61,24,&bord);
	SHOW(137,25,93,14,&k4);	SHOW(167,20,87,24,&bord);
	SHOW(137,25,119,14,&k5);SHOW(167,20,113,24,&bord);
	WSTR(172,116,"\7\17EXIT");
	XOR(y,9,x,4,&curs);
	while(1){
		if(MOUSE){
			XOR(y,9,x,4,&curs);
			x=(xx=MXX)*2+ax;y=(yy=MYY)*2+ay;
			if(x<0) ax-=x;		if(y<0) ay-=y;
			if(x>155) ax-=x-155;	if(y>191) ay-=y-191;
			x=xx*2+ax;y=yy*2+ay;
			XOR(y,9,x,4,&curs);
			mkey();
		}
	}
}
                                                                                                                                                                                                                                                                                                                   