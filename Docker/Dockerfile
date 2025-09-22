FROM debian:bookworm
LABEL maintainer="SYNETIS <cert@synetis.com>"
VOLUME ["/log"]
VOLUME ["/data"]
VOLUME ["/winlogbeat"]
VOLUME ["/hayabusa"]

WORKDIR "/pytriage"
#This is used for kape vhdx mount
RUN apt update -y && \
    apt upgrade -y && \
    apt install -y apt-transport-https apt-utils && \
    apt install -y build-essential && \
    apt install -y mount && \
    apt install -y python3 && \
    apt install -y python3-pip && \
    apt install -y libguestfs-tools && \
    apt install -y zip && \
    apt install -y openssl && \
    apt install -y pkg-config && \
    #apt install -y pff-tools && \
    apt clean -y && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/*

ENV LIBGUESTFS_BACKEND=direct
ENV HOME=/root
#end for kape
COPY . .
RUN pip3 install --upgrade pip --break-system-packages
RUN pip install -r requirements.txt --break-system-packages
RUN pip install src/bin/libpff_python-20240826-cp311-cp311-linux_x86_64.whl --break-system-packages
EXPOSE 8080
CMD ["python3", "triage.py"]