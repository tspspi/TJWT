# Note this makefile only works with TJSON in classpath (setup by
# build system)

SRCS=src/at/tspi/tjwt/JSONWebToken.java \
	src/at/tspi/tjwt/JWTKey.java \
	src/at/tspi/tjwt/exception/JWTTimetraveler.java \
	src/at/tspi/tjwt/exception/JWTTokenExpired.java \
	src/at/tspi/tjwt/exception/JWTValidationException.java \
	src/at/tspi/tjwt/exception/JWTValidInFuture.java

all: bin/TJWT.jar clean

dirs:

	-@mkdir -p bin
	-@mkdir -p classes/at/tspi/tjwt/exception

classes: dirs

	javac -d classes/ $(SRCS)

bin/TJWT.jar: classes

	jar -cvf bin/TJWT.jar -C ./classes .

clean:

	rm -rf ./classes

.PHONY: dirs classes jar
