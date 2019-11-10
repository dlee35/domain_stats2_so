#!/bin/bash

# Check for prerequisites
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run using sudo!"
    exit 1
fi

if [[ ! "$(grep LOGSTASH_ENABLED /etc/nsm/securityonion.conf | cut -f 2 -d\= | tr -d \")" == "yes" ]]; then
    echo "This Security Onion server does not appear to have logstash enabled!"
    exit 1
fi

# Stop logstash and domainstats (if enabled)
echo "Stopping logstash and domainstats (if enabled)..."
/usr/sbin/so-logstash-stop
/usr/sbin/so-domainstats-stop

# Build local container from Dockerfile
if ! docker images | grep -q so-domainstats-test; then
  echo "Building local container named so-domainstats-test..."
  docker build . -t so-domainstats-test
fi

# Creating directory for persistent domain_stats database
if [ ! -d /etc/domain_stats ]; then
  # Temporarily adding this until domain_stats2 pushes ease up 
  git clone https://github.com/MarkBaggett/domain_stats2.git /etc/domain_stats
  #echo "Creating dir for persistent db..."
  #mkdir -p /etc/domain_stats
  chown -R domainstats:domainstats /etc/domain_stats
fi

# do something with --volume /etc/domain_stats:/opt/domain_stats/db
if [ ! -f /etc/nsm/securityonion.conf.bak ]; then
  echo "Backing up /etc/nsm/securityonion.conf to /etc/nsm/securityonion.conf.bak and adjusting DOMAIN_STATS values..."
  sed -i'.bak' -e 's|\(DOMAIN_STATS_ENABLED=\).*|\1"yes"|' -e 's|\(DOMAIN_STATS_OPTIONS=\).*|\1"--volume /etc/domain_stats:/opt/domain_stats"|' /etc/nsm/securityonion.conf
fi
  
if [ ! -f /usr/sbin/so-domainstats-start.bak ]; then
  echo "Backing up /usr/sbin/so-domainstats-start to /usr/sbin/so-domainstats-start.bak, making the backup non-executable, and switching to locally built container..."
  sed -i'.bak' -e 's|\$DOCKERHUB/so-domainstats|so-domainstats-test|' -e 's|\(/var/log/domain_stats\)\:/var/log/domain_stats|\1/domain_stats.log:/opt/domain_stats/domain_stats.log|' /usr/sbin/so-domainstats-start
  touch /var/log/domain_stats/domain_stats.log
  chown -R domainstats: /var/log/domain_stats
  chmod -x /usr/sbin/so-domainstats-start.bak
fi
  
if [ ! -f /usr/sbin/so-logstash-start.bak ]; then
  echo "Backing up /usr/sbin/so-logstash-start to /usr/sbin/so-logstash-start.bak and commenting out domainstats configuration softlinks..."
  sed -i'.bak' '99,102s/^/#/' /usr/sbin/so-logstash-start
  chmod -x /usr/sbin/so-logstash-start.bak
  rm /etc/logstash/conf.d/8007_postprocess_dns_top1m_tagging.conf /etc/logstash/conf.d/8008_postprocess_dns_whois_age.conf
fi
  
if [ ! -f /etc/logstash/custom/8007_postprocess_dns_domainstats.conf ]; then
  echo "Copying new configuration file to /etc/logstash/custom/ ..."
  cp 8007_postprocess_dns_domainstats.conf /etc/logstash/custom/8007_postprocess_dns_domainstats.conf
fi

echo "Starting logstash and domainstats..."
/usr/sbin/so-logstash-start
/usr/sbin/so-domainstats-start

# NOTES
# saw a few of these:
# udp query error [Errno -2] Name or service not known
# Added sleep to Dockerfile for the above issue
