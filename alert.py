import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import conf
import iptc

def banClientFail2Ban(ip):
    cmd = f"sudo fail2ban-client set samba banip {ip} > /dev/null 2>&1"
    os.system(cmd)

def banClientIptables(ip):
    rule = iptc.Rule()
    rule.protocol = "tcp"
    match = rule.create_match('multiport')
    match.dports = "135,139,445,137,138"
    rule.src = ip
    rule.target = iptc.Target(rule, "DROP")
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule)

def sendEmailMonitoring(sender, recipient, subject, message):
    s = smtplib.SMTP(host=conf.config.smtp_host, port=conf.config.smtp_port)
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'html'))
    s.send_message(msg)
