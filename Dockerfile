FROM centos:7
# Got tired of pulling all updates so this was a staged container
#FROM pre-domainstats-2

# Originally developed by Justin Henderson justin@hasecuritysolutions.com
LABEL maintainer "Security Onion Solutions, LLC"

# Create a common centos update layer
RUN yum update -y && \
    yum clean all

# Create a common python/git layer
RUN yum update -y && \
    yum install -y python3 python3-pip git whois which && \
    yum clean all

# Create user
RUN groupadd --gid 936 domainstats && \
    adduser --uid 936 --gid 936 \
      --home-dir /usr/share/domainstats --no-create-home \
      domainstats

# Copy startup script to /opt
#COPY startup.sh /opt/startup.sh
# Placing this here for portability. I know it's ugly.
RUN echo "#! /bin/bash" > /opt/startup.sh && \
    echo "cd /opt/domain_stats" >> /opt/startup.sh && \
    echo "if [ ! -f /opt/domain_stats/db/domain_stats.db ]; then" >> /opt/startup.sh && \
    echo "  /bin/sleep 5" >> /opt/startup.sh && \
    echo "  /bin/bash -c 'echo y | /usr/bin/python3 /opt/domain_stats/database_admin.py --rebuild'" >> /opt/startup.sh && \
    echo "  /usr/bin/python3 /opt/domain_stats/domain_stats.py" >> /opt/startup.sh && \
    echo "else" >> /opt/startup.sh && \
    echo "  /usr/bin/python3 /opt/domain_stats/domain_stats.py" >> /opt/startup.sh && \
    echo "fi" >> /opt/startup.sh

# Install and set perms in same layer to save space
RUN	cd /opt && \
        chmod +x startup.sh && \
        chown domainstats: startup.sh && \
	git clone https://github.com/MarkBaggett/domain_stats2.git domain_stats && \
	pip3 install python-whois pyyaml requests && \
	mkdir /var/log/domain_stats /opt/domain_stats/db && \
        sed -i 's|domain_stats\.db|/opt/domain_stats/db/domain_stats.db|' /opt/domain_stats/domain_stats.yaml && \
	ln -sf /dev/stderr /var/log/domain_stats/domain_stats.log && \
	chown -R domainstats: /opt/domain_stats

USER domainstats

EXPOSE 8000

STOPSIGNAL SIGTERM

ENTRYPOINT /opt/startup.sh
