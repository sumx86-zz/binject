ODIR=obj

ifeq ($(BITS),64)
	override BITS=-DBINJECT64
else
	override BITS=-DBINJECT32
endif

objs:
	@if [ ! -d $(ODIR) ]; then\
		mkdir  $(ODIR);\
	fi

	g++ -Wall $(BITS) -std=c++11 -c binject.cpp -o $(ODIR)/binject.o
	gcc -Wall $(BITS) -c string.c -o $(ODIR)/string.o

all:
	make objs;
	g++ -Wall $(BITS) -std=c++11 $(ODIR)/binject.o $(ODIR)/string.o -o binject

clean:
	rm -f $(ODIR)/*.o

.PHONY: objs, clean, all