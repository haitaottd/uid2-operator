FROM ubuntu:18.04

ENV enclave_platform="aws-nitro"

RUN apt-get update -y
RUN apt install curl -y && apt install build-essential -y && apt install pkg-config libssl-dev -y
RUN apt-get install cmake -y
# install openjdk & maven
RUN apt install openjdk-11-jdk -y && apt install maven -y
# install rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
# install git
RUN apt install git -y

WORKDIR /build
ADD conf ./conf
ADD src ./src
ADD static ./static
COPY setup_dependencies.sh .
COPY ./pom.xml ./pom.xml
RUN chmod +x ./setup_dependencies.sh
RUN ./setup_dependencies.sh
RUN mvn package -Paws -DskipTests=true
