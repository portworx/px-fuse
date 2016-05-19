FROM gcc:latest
MAINTAINER Vinod Jayaraman <jv@portworx.com>

WORKDIR /home/

RUN apt-get update
RUN apt-get install -y  \
	module-init-tools 	\
	dh-autoreconf		\
	alien				\
	rpm

RUN apt-get install -y dh-autoreconf
RUN apt-get install -y rpm alien
RUN apt-get install -y rpm
ADD . /home/px-fuse
WORKDIR /home/px-fuse
RUN autoreconf && ./configure

ENTRYPOINT ["/home/px-fuse/fuse-entry-point.sh"]

CMD ["make", "rpm"]
