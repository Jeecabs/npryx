# npryx sandbox image. Built and tagged by scan-service on first use
# (tag = hash of this directory's files, so edits rebuild automatically).
FROM node:22-slim
RUN useradd --create-home --uid 10001 sandbox
COPY hook.cjs shim-log.cjs entry.sh /npryx/
COPY shims/_shim.sh /npryx/shims/_shim.sh
RUN chmod 755 /npryx/entry.sh /npryx/shims/_shim.sh \
 && for t in curl wget nc ncat netcat socat telnet ssh scp sftp powershell pwsh nslookup dig host ftp tftp; do \
      ln -s /npryx/shims/_shim.sh /npryx/shims/$t; done
USER sandbox
WORKDIR /work
ENTRYPOINT ["/npryx/entry.sh"]
