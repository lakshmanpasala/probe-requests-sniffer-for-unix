# Set the libraries to link
LFLAGS += -lpcap -pthread
CFLAGS += -O2 -s

# The target
TARGET = probe_sniffer
# Object files
OBJECTS = probe_sniffer.o radiotap.o

all: $(TARGET)

# -lm flag required for math.h being used to compute distance
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LFLAGS) -o $(TARGET) -lm
