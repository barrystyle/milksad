CC = g++
CPPFLAGS = -O2 -I. -lssl -lcrypto -lsecp256k1 -Wno-deprecated-declarations

OBJ =   \
	base58.o                            \
	bech32.o                            \
	bip32.o                             \
	bip39.o                             \
	db.o                                \
	derive.o                            \
	entropy.o                           \
	main.o                              \
	worker.o                            \
	tests.o                             \
	simplelogger.o                      \
	crypto/hmac_sha512.o                \
	crypto/pkcs5_pbkdf2_hmac_sha512.o   \
	crypto/sha512.o

%.o: %.cpp
	$(CC) -c -o $@ $< $(CPPFLAGS)

milksad: $(OBJ)
	$(CC) -o $@ $^ $(CPPFLAGS)

all:    milksad
clean:
	rm -f milksad
	rm -f *.o
	rm -f */*.o
