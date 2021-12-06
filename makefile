LDLIBS=-lpcap

all: airodump

airodump: main.o mac.o airodump.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o 
