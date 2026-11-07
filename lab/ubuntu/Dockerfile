FROM ubuntu:24.04
COPY setup.sh entrypoint.sh /root/
RUN bash /root/setup.sh && rm /root/setup.sh
CMD ["bash", "/root/entrypoint.sh"]
