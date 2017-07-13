OBJS=main.o
TARGET=txt-error-codes
CFLAGS=-g -Wall -Werror
LDFLAGS=-g -Wall -Werror

all: txt-error-codes

$(TARGET): $(OBJS)
	gcc -o $@ $^

clean:
	rm $(TARGET) $(OBJS)

run: $(TARGET)
	./$^ 0xc0031c61
