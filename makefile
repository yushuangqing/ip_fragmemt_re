pcaptest : list.o main.o
	gcc -g  -o pcaptest  list.o main.o  -lpcap

main.o: main.c list.h
	gcc -c -Wall -g main.c 
list.o: list.c list.h
	gcc -c -Wall -g  list.c

.PHONY : clean
clean :
	rm pcaptest *.o
