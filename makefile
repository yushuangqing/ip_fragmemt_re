obj=list.o main.o fragment.o auto_get_packet.o reassembled.o

pcaptest : ${obj}
	gcc -g  -o pcaptest ${obj} -lpcap

main.o: main.c list.h fragment.h auto_get_packet.h auto_get_packet.h
	gcc -c -Wall -g main.c 
list.o: list.c list.h
	gcc -c -Wall -g  list.c
fragment.o: fragment.c fragment.h
	gcc -c -Wall -g  fragment.c 
auto_get_packet.o: auto_get_packet.c auto_get_packet.h fragment.h
	gcc -c -Wall -g  auto_get_packet.c 
reassembled.o: reassembled.c reassembled.h
	gcc -c -Wall -g  reassembled.c 
	
.PHONY : clean
clean :
	rm pcaptest *.o
