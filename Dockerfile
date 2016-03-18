FROM gcc:latest
MAINTAINER Vinod Jayaraman <jv@portworx.com>

WORKDIR /home/

RUN apt-get update
RUN apt-get install -y  module-init-tools   
ADD . /home/px-fuse
#RUN git clone https://github.com/portworx/px-fuse
WORKDIR /home/px-fuse
RUN autoreconf && ./configure

CMD make
