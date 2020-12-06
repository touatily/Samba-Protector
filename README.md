## Wishare Protector

# Samba configuration:

In `smb.conf`, at the end of section `[global]`, add these lines:
```
# AUDIT
   vfs objects = full_audit
   full_audit:prefix = %T|%I|%m|%S
   full_audit:success = ftruncate readlink pread read rename rmdir unlink pwrite write connect disconnect open
   full_audit:failure = ftruncate readlink pread read rename rmdir unlink pwrite write connect disconnect open
   full_audit:facility = LOCAL4
   full_audit:priority = INFO
```

This configuration allows to prints log lines as (for example):
```
Example:
Sep 25 15:35:40 ubuntu-bionic smbd_audit[8664]: 2020/09/25 15:35:40|10.11.12.13|ubuntu-bionic|lyes|open|ok|r|t
```

# Syslog Configuration

create the file `/etc/syslog-ng/conf.d/samba.conf` and write these lines to it:

```
filter f_samba_audit { facility(local4) ; };

destination d_samba_audit1 { file("/var/log/samba_audit.log"); };
destination d_samba_audit { syslog("127.0.0.1" transport(udp) port(524) ); };

log { source(s_src); filter(f_samba_audit); destination(d_samba_audit1); };
log { source(s_src); filter(f_samba_audit); destination(d_samba_audit); };
```

This allows to write logs in the file `/var/log/samba_audit.log` and send syslog traffic to 127.0.0.1:524 (UDP).

If you change port number in `samba.conf`, you have to specify the same port number in config.ini.sample

# Fail2ban (install & configuration):

- Install fail2ban (deprecated: replaced by iptables):
`sudo apt install fail2ban`

- Create the file '/etc/fail2ban/jail.d/samba.conf' with the content bellow:
```
[samba]
enabled = true
port = 135,139,445,137,138
bantime = 10m
```
Change `10m` to the duration you want banned hosts to stay in jail! `-1` to specify permament ban


# WishareProtector Configuration:

The name of the configuration file is `conf.conf`.

WishareProtector allows you to define many policies. If, at least, one of these policies is not respected by a host it is banned.

For the moment, there are two types of policies:

- type 1: based on the number of operations
- type 2: based on the filname pattern

Two policy samples are provided in the configuration file.

The configuration file contains also other options like: monitoring email, log file, samba log file, log level.

# Virtual environnement:

Install `venv` module first (if not aleardy installed). Then, create a vitual environnement using command:

```
sudo apt-get install python3-venv
cd /<path>/<where>/<to>/<create>/
python3 -m venv wp_venv
```

Install requirements

```
/<path>/<where>/<to>/<create>/wp_venv/bin/pip3 install -r requirements.txt
```

Replace python3 path in `wishareprotector.service` by /<path>/<where>/<to>/<create>/wp_venv/bin/python3`

# Deployment as Linux service:

## Save "/etc/systemd/system/" in a temporary directory:
  sudo cp -r /etc/systemd/system /etc/systemd/system.save$(date +%Y%m%d)

## copy "wishareprotector.service" in "/etc/systemd/system/"
## replace python3 path by venv python3 path (see section `Virtual environnement`)
## replace main.py and conf.conf paths by yours
  sudo cp wishareprotector.service /etc/systemd/system/

## enable service "wishareprotector.service"
  sudo systemctl enable wishareprotector.service

## start servcie "wishareprotector.service"
  sudo systemctl start wishareprotector.service
