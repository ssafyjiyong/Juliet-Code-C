FROM gcc:11.2.0
LABEL maintainer="SAMATE, NIST"
WORKDIR /sard
RUN apt-get update && apt-get install -y --no-install-recommends curl make unzip
RUN mkdir -p stonesoup
RUN ln -s $PWD/stonesoup /opt/stonesoup
COPY . .
