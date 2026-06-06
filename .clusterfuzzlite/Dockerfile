FROM gcr.io/oss-fuzz-base/base-builder-python

COPY . $SRC/agent-guardian
COPY .clusterfuzzlite/build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh
WORKDIR $SRC/agent-guardian
