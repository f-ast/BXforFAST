FROM yijun/fast
RUN apk add -U --no-cache gmp
RUN apk add -U --no-cache openjdk8
ENV PATH /usr/lib/jvm/java-1.8-openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ADD . /bx4fast
WORKDIR /bx4fast
