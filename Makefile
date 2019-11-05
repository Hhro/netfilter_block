EXEC = netfilter_block
C = gcc

$(EXEC):
	$(C) -o $(EXEC) main.c -lnetfilter_queue

clean:
	rm $(EXEC)