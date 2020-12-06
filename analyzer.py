import socket
import logger as log
from datetime import datetime
import conf as cf
from datetime import timedelta
import alert

class analyzer:
    sock = None
    local_ip = cf.config.syslog_IP
    local_port = cf.config.syslog_port
    buffer_size = 1024
    parsed_data = {}     # stores all parsed syslog traffic

    @classmethod
    def processPacket(cls, packet):
        # Packets Samples:
        # connect: b'<166>1 2020-10-01T15:17:20+02:00 ubuntu-bionic smbd_audit 3674 - - 2020/10/01 15:17:20|10.11.12.1|dhcp-13-208|lyes|connect|ok|lyes'
        # diconnect: b'<166>1 2020-10-01T15:18:47+02:00 ubuntu-bionic smbd_audit 3674 - - 2020/10/01 15:18:47|10.11.12.1|dhcp-13-208|lyes|disconnect|ok|lyes'
        # read: b'<166>1 2020-10-01T15:19:54+02:00 ubuntu-bionic smbd_audit 3683 - - 2020/10/01 15:19:54|10.11.12.1|dhcp-13-208|lyes|open|ok|r|file'
        # write: b'<166>1 2020-10-01T15:20:23+02:00 ubuntu-bionic smbd_audit 3683 - - 2020/10/01 15:20:23|10.11.12.1|dhcp-13-208|lyes|open|ok|w|filename'
        # delete: b'<166>1 2020-10-01T15:21:26+02:00 ubuntu-bionic smbd_audit 3683 - - 2020/10/01 15:21:26|10.11.12.1|dhcp-13-208|lyes|unlink|ok|filetest'
        # rename: b'<166>1 2020-10-01T15:21:03+02:00 ubuntu-bionic smbd_audit 3683 - - 2020/10/01 15:21:03|10.11.12.1|dhcp-13-208|lyes|rename|ok|file|filetest'

        data = packet.decode().split(" - - ")[1].split("|")
        time = datetime.strptime(data[0], "%Y/%m/%d %H:%M:%S")
        ip = data[1]
        hostname = data[2]
        shared_path = data[3]
        action = data[4]
        status = data[5]

        act = action     # by default, it takes the value of action
        filename = None
        if action not in ("open", "connect", "disconnect", "unlink", "rename"):
            return
        if action == "open" and status == "ok":
            if data[7] != ".":
                if data[6] == "r": # reading file
                    act = "read"
                else:              # writing file
                    act = "write"
                filename = data[7]
            else:
                return   # ignore reading directories
        elif action == "unlink":
            act = "delete"
            filename = data[6]
        elif action == "rename":
            filename = data[7]       # get the new name
        elif action == "connect" or action == "disconnect":
            if data[6] == "IPC$":
                return   # ignore connect/disconnect when share is IPC$

        if ip not in cls.parsed_data.keys():
            cls.parsed_data[ip] = { "history": { "read":[], "write":[],
                                            "delete":[], "rename": [],
                                            "connect":[], "disconnect":[] },
                                    "modified": True }

        cls.parsed_data[ip]["history"][act].append((time, filename))
        cls.parsed_data[ip]["modified"] = True

    @classmethod
    def checkPolicyHost(cls, ip, policy, data=None):
        """ check one host, one policy """
        if policy["type"] == cf.config.POLICY_NB_OPERATIONS:
            for op in policy["details"]:
                nb_elts = len(cls.parsed_data[ip]["history"][op["type"]])
                if nb_elts <= op["threshold"]:
                    return True
                elif op["period"] < cf.config.max_period_policy:
                    start_interval = datetime.now() + timedelta(0, -int(op["period"]))
                    nb_elts = len( (*filter(lambda time: time[0] >= start_interval, cls.parsed_data[ip]["history"][op["type"]]),) )
                    if nb_elts <= op["threshold"]:
                        return True
            # if not return False
            return False
        elif policy["type"] == cf.config.POLICY_FILENAME_PATTERN:
            # we check this policy only for the last parsed data
            l = []
            for act in cls.parsed_data[ip]["history"].keys():
                if act in ("write", "read", "delete", "rename"):
                    if len(cls.parsed_data[ip]["history"][act]) != 0:
                        l += [cls.parsed_data[ip]["history"][act][-1] + (act,)]
            if l != []:
                data = max(l, key=lambda x: x[0])
                op = {"read":"r", "write":"w", "rename":"w", "delete":"d"}[data[2]]
                if op in policy["ops"]:
                    # we have to check filename
                    if policy["regex"].match(data[1]):
                        return False

            # in all else blocks return True
            return True

        # add "elif policy["type"] == 3" here if new type of policy is to be dfined.

    @classmethod
    def checkPoliciesHost(cls, ip, policies):
        if cls.parsed_data[ip]["modified"]:
            cls.parsed_data[ip]["modified"] = False
            for policy in policies:
                r = cls.checkPolicyHost(ip, policy)
                #print(ip, policies)
                if not r:
                    return (False, policy)
        # In both else blocks, return True (policies are respected)
        return (True, None)


    @classmethod
    def checkPolicies(cls, policies):
        for ip, details in cls.parsed_data.items():
            policies_respected, p = cls.checkPoliciesHost(ip, policies)
            # p is the first tested policy that is not respected if there is any (else None)
            if not policies_respected:
                log.logger.critical(f"Host [{ip}] didn't respect policy [{p['name']}]")
                #print(cls.parsed_data[ip])
                # sending emails to monitoring@withings.com
                log.logger.info(f"Sending email to {cf.config.monitoring_email} to report the event")
                sender = "wishare_protector@withings.com"
                recipient = cf.config.monitoring_email
                subject = f"Wishare alert: Policy [{p['name']}] not respected"
                message = f"Hello,<br/><br/>WishareProtector has just detected that host "\
                            f"<b>[{ip}]</b> didn't respect policy <b>[{p['name']}]</b><br/><br/>"\
                            f"Details about the event:<br/>"\
                            f"<ul>"\
                            f"<li>Time: <b>{datetime.now()}</b></li>"\
                            f"<li>policy: <b>{p}</b></li>"\
                            f"</ul><br/>"\
                            f"This host <b>[{ip}]</b> will be banned immediately"

                alert.sendEmailMonitoring(sender, recipient, subject, message)

                # banning suspecious host
                log.logger.info(f"Banning host [{ip}]")
                #alert.banClientFail2Ban(ip)
                alert.banClientIptables(ip)


    @classmethod
    def removeOldActions(cls):
        """ remove old actions """
        now = datetime.now()
        start_interval = now + timedelta(0,-cf.config.max_period_policy)
        for _, v in cls.parsed_data.items():
            for k in v["history"].keys():
                v["history"][k] = [*filter(lambda time: time[0] >= start_interval, v["history"][k])]


    @classmethod
    def mainloop(cls):
        cls.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        cls.sock.bind((cls.local_ip, cls.local_port))

        log.logger.info(f"UDP server up and listening syslog traffic [{cls.local_ip}:{cls.local_port}]")
        while True:
            data = cls.sock.recvfrom(cls.buffer_size)
            #print(data)
            cls.processPacket(data[0].strip(b"\n"))   # ignore "\n" at the end
            cls.removeOldActions()
            cls.checkPolicies(cf.config.policies)
