all: netfilter_block

netfilter_block: main.c
	g++ -o netfilter_block main.c -lnetfilter_queue

clean:
	rm -f netfilter_block
