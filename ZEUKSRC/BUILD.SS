tkHuft:
	mov	nmem,-(sp)
	add	r0,nmem
	mov	(sp)+,r0
	set
	return

build:
	$b=4
	$n=6
	$s=10
	$d=12
	$e=14
	$t=16
	$m=20

L2:	$a=177770
	$c=177726
	$f=177724
	$g=177722
	$h=177720
	$i=177716
	$j=177714
	$k=177712
	$l=177710
	$p=177706
	$q=177704
	$r=177700
	$u=177640
	$v=176540
	$w=176536
	$x=176474
	$xp=176472
	$y=176470
	$z=176466

	bug	..bu,___build_beg
;	mov	#42,(sp)
;	clr	-(sp)
;	mov	r5,-(sp)
;	add	#-52,(sp)
;	jsr	pc,*$_memset
;	cmp	(sp)+,(sp)+
	mov	r5,r0
	add	#-52,r0
	mov	#42,r1
1$:	clrb	(r0)+
	sob	r1,1$


	mov	4(r5),-72(r5)
	mov	6(r5),-62(r5)
L6:	mov	@-72(r5),r0
	asl	r0
	add	#2,-72(r5)
	add	r5,r0
	inc	-52(r0)
L4:	dec	-62(r5)
	bne	L6
L5:	cmp	6(r5),-52(r5)
	bne	L7
	clr	@16(r5)
	clr	@20(r5)
	clr	r0
	jmp	L3
L7:	mov	@20(r5),-70(r5)
	mov	#1,-64(r5)
L8:	cmp	#20,-64(r5)
	blo	L9
	mov	-64(r5),r0
	asl	r0
	add	r5,r0
	tst	-52(r0)
	bne	L9
L10:	inc	-64(r5)
	br	L8
L9:	mov	-64(r5),-66(r5)
	cmp	-64(r5),-70(r5)
	blos	L11
	mov	-64(r5),-70(r5)
L11:	mov	#20,-62(r5)
L12:	tst	-62(r5)
	beq	L13
	mov	-62(r5),r0
	asl	r0
	add	r5,r0
	tst	-52(r0)
	bne	L13
L14:	dec	-62(r5)
	br	L12
L13:	mov	-62(r5),-56(r5)
	cmp	-62(r5),-70(r5)
	bhis	L15
	mov	-62(r5),-70(r5)
L15:	mov	-70(r5),@20(r5)
	mov	#1,r0
	ash	-64(r5),r0
	mov	r0,-1310(r5)
L16:	cmp	-62(r5),-64(r5)
	blos	L17
	mov	-64(r5),r0
	asl	r0
	add	r5,r0
	sub	-52(r0),-1310(r5)
	bge	L19
	mov	#2,r0
	jmp	L3
L19:
L18:	inc	-64(r5)
	asl	-1310(r5)
	br	L16
L17:	mov	-62(r5),r0
	asl	r0
	add	r5,r0
	sub	-52(r0),-1310(r5)
	bge	L20
	mov	#2,r0
	jmp	L3
L20:	mov	-1310(r5),r0
	mov	-62(r5),r1
	asl	r1
	add	r5,r1
	add	r0,-52(r1)
	clr	r0
	mov	r0,-64(r5)
	mov	r0,-1302(r5)
	mov	r5,r0
	add	#-50,r0
	mov	r0,-72(r5)
	mov	r5,r0
	add	#-1300,r0
	mov	r0,-1306(r5)
L21:	dec	-62(r5)
	beq	L22
	add	@-72(r5),-64(r5)
	add	#2,-72(r5)
	mov	-64(r5),@-1306(r5)
	add	#2,-1306(r5)
	br	L21
L22:	mov	4(r5),-72(r5)
	clr	-62(r5)
L25:	mov	-72(r5),r0
	add	#2,-72(r5)
	mov	(r0),-64(r5)
	beq	L26
	mov	-64(r5),r1
	asl	r1
	add	r5,r1
	mov	-1304(r1),r0
	inc	-1304(r1)
	asl	r0
	add	r5,r0
	mov	-62(r5),-1240(r0)
L26:
L23:	inc	-62(r5)
	cmp	6(r5),-62(r5)
	bhi	L25
L24:	clr	r0
	mov	r0,-62(r5)
	mov	r0,-1304(r5)
	mov	r5,r0
	add	#-1240,r0
	mov	r0,-72(r5)
	mov	#-1,-60(r5)
	mov	-70(r5),r0
	neg	r0
	mov	r0,-1242(r5)
	clr	-140(r5)
	clr	-74(r5)
	clr	-1312(r5)
L27:	cmp	-56(r5),-66(r5)
	blt	lL28
	mov	-66(r5),r0
	asl	r0
	add	r5,r0
	mov	-52(r0),-10(r5)
L30:	mov	-10(r5),r0
	dec	-10(r5)
	tst	r0
	beq	lL31
L32:	mov	-1242(r5),r0
	add	-70(r5),r0
	cmp	-66(r5),r0
	ble	lL33
	inc	-60(r5)
	add	-70(r5),-1242(r5)
	mov	-56(r5),r0
	sub	-1242(r5),r0
	mov	r0,-1312(r5)
	cmp	-70(r5),r0
	bhis	L10000
	mov	-70(r5),r0
	br	L10001
ll33:	jmp	l33
ll31:	jmp	l31
ll28:	jmp	l28
L10000:	mov	-1312(r5),r0
L10001:	mov	r0,-1312(r5)
	mov	#1,r0
	mov	-66(r5),r1
	sub	-1242(r5),r1
	mov	r1,-64(r5)
	ash	r1,r0
	mov	r0,-54(r5)
	mov	-10(r5),r1
	inc	r1
	cmp	r1,r0
	bhis	L34
	mov	-10(r5),r0
	inc	r0
	sub	r0,-54(r5)
	mov	-66(r5),r0
	asl	r0
	add	r5,r0
	add	#-52,r0
	mov	r0,-1306(r5)
L35:	inc	-64(r5)
	cmp	-1312(r5),-64(r5)
	blos	L36
	add	#2,-1306(r5)
	mov	-54(r5),r0
	ash	#1,r0
	mov	r0,-54(r5)
	cmp	@-1306(r5),r0
	bhis	L36
	sub	@-1306(r5),-54(r5)
	jmp	L35
L36:
L34:
	mov	#1,r0
	ash	-64(r5),r0
	mov	r0,-1312(r5)
	mov	-1312(r5),r0
	inc	r0
	ash	#2,r0
;	mov	r0,(sp)
;	***sr	pc,*$_malloc
	call	tkHuft
	mov	r0,-74(r5)
	bne	L37
	tst	-60(r5)
	beq	L38
;	mov	-140(r5),(sp)
;	***jsr	pc,*$_huft_fr
L38:	mov	#3,r0
	jmp	L3
L37:	mov	-1312(r5),r0
	inc	r0
;	add	r0,_hufts
	mov	-74(r5),r0
	add	#4,r0
	mov	r0,@16(r5)
	mov	-74(r5),r0
	add	#2,r0
	mov	r0,16(r5)
	clr	(r0)
	add	#4,-74(r5)
	mov	-60(r5),r0
	asl	r0
	add	r5,r0
	mov	-74(r5),-140(r0)
	tst	-60(r5)
	beq	L39
	mov	-60(r5),r0
	asl	r0
	add	r5,r0
	mov	-62(r5),-1304(r0)
	movb	-70(r5),-77(r5)
	mov	-64(r5),r0
	add	#20,r0
	movb	r0,r0
	movb	r0,-100(r5)
	mov	-74(r5),-76(r5)
	mov	-62(r5),r1
	clr	r0
	mov	-1242(r5),r2
	sub	-70(r5),r2
	neg	r2
	ashc	r2,r0
	mov	r1,-64(r5)
	mov	-60(r5),r0
	asl	r0
	add	r5,r0
	mov	-142(r0),r0
	mov	-64(r5),r1
	ash	#2,r1
	add	r1,r0
	mov	-76(r5),+2(r0)
	mov	-100(r5),(r0)
L39:	jmp	L32
L33:	mov	-66(r5),r0
	sub	-1242(r5),r0
	movb	r0,r0
	movb	r0,-77(r5)
	mov	6(r5),r0
	asl	r0
	add	r5,r0
	add	#-1240,r0
	cmp	-72(r5),r0
	blo	L40
	movb	#143,-100(r5)
	br	L41
L40:	cmp	10(r5),@-72(r5)
	blos	L42
	cmp	#400,@-72(r5)
	blos	L10002
	mov	#20,r0
	br	L10003
L10002:	mov	#17,r0
L10003:	movb	r0,r0
	movb	r0,-100(r5)
	mov	@-72(r5),-76(r5)
	add	#2,-72(r5)
	br	L43
L42:	mov	@-72(r5),r0
	sub	10(r5),r0
	asl	r0
	add	14(r5),r0
	mov	(r0),r0
	movb	r0,r0
	movb	r0,-100(r5)
	mov	@-72(r5),r0
	sub	10(r5),r0
	add	#2,-72(r5)
	asl	r0
	add	12(r5),r0
	mov	(r0),-76(r5)
L43:
L41:	mov	#1,r0
	mov	-66(r5),r1
	sub	-1242(r5),r1
	ash	r1,r0
	mov	r0,-54(r5)
	mov	-62(r5),r1
	clr	r0
	mov	-1242(r5),r2
	neg	r2
	ashc	r2,r0
	mov	r1,-64(r5)
L44:	cmp	-1312(r5),-64(r5)
	blos	L45
	mov	-64(r5),r0
	ash	#2,r0
	add	-74(r5),r0
	mov	-76(r5),+2(r0)
	mov	-100(r5),(r0)
L46:	add	-54(r5),-64(r5)
	br	L44
L45:	mov	#1,r0
	mov	-66(r5),r1
	dec	r1
	ash	r1,r0
	mov	r0,-64(r5)
L47:	bit	-64(r5),-62(r5)
	beq	L48
	mov	-64(r5),r0
	xor	r0,-62(r5)
	mov	-62(r5),r0
L49:	mov	-64(r5),r1
	clr	r0
	ashc	#-1,r0
	mov	r1,-64(r5)
	br	L47
L48:	mov	-64(r5),r0
	xor	r0,-62(r5)
	mov	-62(r5),r0
L50:	mov	#1,r0
	ash	-1242(r5),r0
	dec	r0
	mov	-62(r5),r1
	com	r1
	bic	r1,r0
	mov	-60(r5),r1
	asl	r1
	add	r5,r1
	cmp	-1304(r1),r0
	beq	L51
	dec	-60(r5)
	sub	-70(r5),-1242(r5)
	br	L50
L51:	jmp	L30
L31:
L29:	inc	-66(r5)
	jmp	L27
L28:	tst	-1310(r5)
	beq	L10005
	cmp	#1,-56(r5)
	bne	L10004
L10005:	clr	r0
	br	L10006
L10004:	mov	#1,r0
L10006:
L3:	bug	..be,____build_end
	cmp	#1,r0
	blo	2$
	tst	(pc)+
2$:	sec
1$:	return
                                                                                                                                                                                                                                         