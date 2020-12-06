import configparser
import json
import re
import sys
import argparse

class config:
    loaded = False
    policies = []
    samba_logfile = ""
    logfile = ""
    monitoring_email = ""
    log_level = ""
    possible_log_level = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    max_period_policy = 5

    syslog_port = 514
    syslog_IP = "127.0.0.1"

    # Constants:
    POLICY_NB_OPERATIONS = 1
    POLICY_FILENAME_PATTERN = 2
    # add other constants here if other typesof policies are defined

    @classmethod
    def loadConfig(cls, config_file):
        if cls.loaded:    # do not load again if already loaded
            return
        cls.loaded = True

        conf = configparser.ConfigParser()
        conf.read(config_file)
        # variables section
        if "variables" in conf.sections():
            if "samba_logfile" in conf["variables"]:
                cls.samba_logfile = conf["variables"]["samba_logfile"]
            else:
                raise Exception("Samba logfile path not defined")
            if "logfile" in conf["variables"]:
                cls.logfile = conf["variables"]["logfile"]
            else:
                raise Exception("Logfile path not defined")
            if "monitoring_email" in conf["variables"]:
                cls.monitoring_email = conf["variables"]["monitoring_email"]
            else:
                raise Exception("Monitoring email not defined")
            if "log_level" in conf["variables"]:
                if conf["variables"]["log_level"] in cls.possible_log_level:
                    cls.log_level = conf["variables"]["log_level"]
                else:
                    Exception("Log level value not allowed")
            else:
                cls.log_level = "INFO"

            # STMP configuration: Host & port
            if "smtp_host" in conf["variables"]:
                cls.smtp_host = conf["variables"]["smtp_host"]
            else:
                raise Exception("SMTP host required in configuration")
            if "smtp_port" in conf["variables"]:
                cls.smtp_port = conf["variables"]["smtp_port"]
            else:
                raise Exception("SMTP port required in configuration")

            # Listening server: Host & port
            if "syslog_IP" in conf["variables"]:
                cls.syslog_IP = conf["variables"]["syslog_IP"]
            else:
                raise Exception("Listening server IP required in configuration")
            if "syslog_port" in conf["variables"]:
                cls.syslog_port = int(conf["variables"]["syslog_port"])
            else:
                raise Exception("Listening server port required in configuration")
        else:
            raise Exception("Section \"variables\" not defined in configuration file")

        # policies section
        if "policies" in conf.sections():
            for policy in conf["policies"]:
                pj = json.loads(conf["policies"][policy])
                if pj["type"] == cls.POLICY_FILENAME_PATTERN:
                    ops = pj["ops"]
                    pj["ops"] = [*set(pj["ops"].split("/"))]  # remove duplicate if any
                    # check operations are valid
                    if any([e not in ("w", "r", "d") for e in pj["ops"]]):
                        raise Exception(f"Operation not recognized in policy type 2: {ops}")
                    try:
                        pj["regex"] = re.compile(pj["pattern"])
                    except Exception as e:
                        raise e            # useless but may change in the futur

                elif pj["type"] == cls.POLICY_NB_OPERATIONS:
                    for op in pj["details"]:
                        if op["period"] > cls.max_period_policy:
                            cls.max_period_policy = op["period"]
                cls.policies.append(pj)
            if len(cls.policies) == 0:
                raise Exception("No defined policy in configuration file")
        else:
            raise Exception("Section \"policies\" missing")
