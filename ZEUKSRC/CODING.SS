Inflate:
	$$tl=4
	$$td=6
	$$bl=10
	$$bd=12
Z2:
	$$e=177770
	$$n=177766
	$$d=177764
	$$w=177762
	$$t=177760
	$$ml=177756
	$$md=177754

	bug	..cb,_____coding_beg
	set

	mov	10(r5),r0
	asl	r0
	mov	maskbi(r0),-22(r5)
	mov	12(r5),r0
	asl	r0
	mov	maskbi(r0),-24(r5)
Z4:
	mov	10(r5),r1
	needbits

	mov	b,r0
	mov	-22(r5),r1
	com	r1
	bic	r1,r0
	ash	#2,r0
	add	4(r5),r0
	mov	r0,-20(r5)
	movb	(r0),r0
	bic	#^c377,r0
	mov	r0,-10(r5)
	cmp	#20,r0
	bhis	Z6
Z9:	cmp	#143,-10(r5)
	bne	Z10
	mov	#1,r0
	jmp	Z3
Z10:	mov	-20(r5),r0
	movb	1(r0),r0

	mov	r0,r1
	dumpbits

	sub	#20,-10(r5)

	mov	-10(r5),r1
	needbits

Z7:	mov	-10(r5),r0
	asl	r0
	mov	maskbi(r0),r0
	mov	b,r1
	com	r1
	bic	r1,r0
	ash	#2,r0
	mov	-20(r5),r1
	add	2(r1),r0
	mov	r0,-20(r5)
	movb	(r0),r0
	bic	#^c377,r0
	mov	r0,-10(r5)
	cmp	#20,r0
	blo	Z9
Z8:
Z6:
	mov	-20(r5),r0
	movb	1(r0),r0

	mov	r0,r1
	dumpbits

	cmp	#20,-10(r5)
	bne	Z11
	mov	-20(r5),r0
	mov	2(r0),r0
	movb	r0,r0

	bug	..jpc,_____Just_put_sym
	call	xPutSym

	jmp	Z12
zz5:	jmp	z5

Z11:	cmp	#17,-10(r5)
	beq	zZ5

	mov	-10(r5),r1
	needbits

	mov	-10(r5),r0
	asl	r0
	mov	maskbi(r0),r0
	mov	b,r1
	com	r1
	bic	r1,r0
	mov	-20(r5),r1
	add	2(r1),r0
	mov	r0,-12(r5)

	mov	-10(r5),r1
	dumpbits

	mov	12(r5),r1
	needbits

	mov	b,r0
	mov	-24(r5),r1
	com	r1
	bic	r1,r0
	ash	#2,r0
	add	6(r5),r0
	mov	r0,-20(r5)
	movb	(r0),r0
	bic	#^c377,r0
	mov	r0,-10(r5)
	cmp	#20,r0
	bhis	Z13
Z16:	cmp	#143,-10(r5)
	bne	Z17
	mov	#1,r0
	jmp	Z3
Z17:	mov	-20(r5),r0
	movb	1(r0),r0

	mov	r0,r1
	dumpbits

	sub	#20,-10(r5)

	mov	-10(r5),r1
	needbits

Z14:	mov	-10(r5),r0
	asl	r0
	mov	maskbi(r0),r0
	mov	b,r1
	com	r1
	bic	r1,r0
	ash	#2,r0
	mov	-20(r5),r1
	add	2(r1),r0
	mov	r0,-20(r5)
	movb	(r0),r0
	bic	#^c377,r0
	mov	r0,-10(r5)
	cmp	#20,r0
	blo	Z16
Z15:
Z13:	mov	-20(r5),r0
	movb	1(r0),r0

	mov	r0,r1
	dumpbits

	mov	-10(r5),r1
	needbits

	mov	outptr,r0
	mov	-20(r5),r1
	sub	2(r1),r0
	mov	-10(r5),r1
	asl	r1
	mov	maskbi(r1),r1
	mov	b,r2
	com	r2
	bic	r2,r1
	sub	r1,r0
	mov	r0,-14(r5)

	mov	-10(r5),r1
	dumpbits

	bug	..psb,_____put_str
	.reset
Z20:
	mov	-14(r5),r1
	inc	-14(r5)
	bic	#cbuf,r1
	add	outbuf,r1
	movb	(r1)+,r0
	call	PutSym	
	tst	ZipEof
	bne	zzz1
	dec	-12(r5)
	bne	Z20
	set
	bug	..epsb,____end_put_str
Z19:
Z12:	jmp	Z4
Z5:	clr	r0
Z3:	bug	..eb,____coding_end
	tst	r0
	beq	zzz2
zzz1:	sec
zzz2:	return
                                                                            