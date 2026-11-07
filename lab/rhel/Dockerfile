FROM almalinux:9
COPY setup.sh entrypoint.sh /root/
RUN bash /root/setup.sh && rm /root/setup.sh
CMD ["bash", "/root/entrypoint.sh"]
