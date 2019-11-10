# domain_stats2_so

### The setup script is to be used by those running Security Onion using the traditional Logstash pipeline (not LOGSTASH_MINIMAL). Everything will be configured without any manual modifications required.

run `sudo bash setup.sh`

### However, if you are leveraging the minimal installation via `sosetup-minimal`, something else will have to communicate with domain_stats2. The steps below must be followed carefully.

Perform the following steps to have Bro/Zeek create a new `domainstats.log` using Bro/Zeek's [ActiveHTTP](https://docs.zeek.org/en/stable/scripts/base/utils/active-http.zeek.html)
- run the setup script as above
- add ' -p 20000:8000' to **DOCKER_OPTIONS** in `/etc/nsm/securityonion.conf`
- edit the syslog-ng config located at `/etc/syslog-ng/syslog-ng.conf` and add:
  - `source s_bro_domainstats { file("/nsm/bro/logs/current/domainstats.log" flags(no-parse) program_override("bro_domainstats")); };`
  - `source(s_bro_domainstats);` to the `log` stanza
- copy `bro_domainstats` to `/etc/elasticsearch/ingest/`
- add the new Bro/Zeek script:
  - `sudo mkdir /opt/bro/share/bro/policy/domainstats`
  - `echo '@load ./domainstats' | sudo tee -a /opt/bro/share/bro/policy/domainstats/__load__.bro`
  - `sudo cp domainstats.bro /opt/bro/share/bro/policy/domainstats/`
  - `echo '@load domainstats' | sudo tee -a /opt/bro/share/bro/site/local.bro`
- copy `logstash-template.json` to `/etc/logstash/custom/`
- `sudo systemctl restart syslog-ng`
- `sudo so-bro-restart`
- `sudo so-elastic-restart`
- `sudo so-elasticsearch-pipelines`

*I'll eventually add logic in the setup script to check for minimal installs (plus storage & forward nodes) and the above will be deprecated :crosses fingers:...*
