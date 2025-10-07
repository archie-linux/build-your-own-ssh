CC = gcc  # Use Homebrew's GCC (adjust version if needed)
CFLAGS = -Wall -g -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
TARGETS = ssh_server ssh_client generate_keys

all: $(TARGETS)

ssh_server: ssh_server.c
	$(CC) $(CFLAGS) ssh_server.c -o ssh_server $(LDFLAGS)

ssh_client: ssh_client.c
	$(CC) $(CFLAGS) ssh_client.c -o ssh_client $(LDFLAGS)

generate_keys: generate_keys.c
	$(CC) $(CFLAGS) generate_keys.c -o generate_keys $(LDFLAGS)

clean:
	rm -rf $(TARGETS) *.crt *.key *.pub *.dSYM users.txt *.log
