import libsecurityappsldap as ldaplib
import splunklib.client as client
import re
import splunklib.results as results
import io
import ConfigParser as CP
import sys
import psycopg2 as ps2
import os
import subprocess
import smtplib


class ResponseReaderWrapper(io.RawIOBase):

    """Splunk ResultReader wrapper to speed up IO from Splunk
       Credit to senior design team for this solution:
            David Engel
            Kyle Heitman
            Gavin Li
            Tony Pham
            Nathan Ramdial
    """

    def __init__(self, responseReader):
        self.responseReader = responseReader

    def readable(self):
        return True

    def close(self):
        self.responseReader.close()

    def read(self, n):
        return self.responseReader.read(n)

    def readinto(self, b):
        size = len(b)
        data = self.responseReader.read(size)
        for idx, ch in enumerate(data):
            b[idx] = ch

        return len(data)

def connect_to_splunk():

    scp = CP.ConfigParser()
    
    conf = "/etc/geode/settings.conf"
    scp.read(conf)
    s = "Splunk"
    username = scp.get(s, "username")
    password = scp.get(s, "password")
    port = scp.get(s, "port")
    host = scp.get(s, "host")

    try:
        conn = client.connect(username=username, password=password, port=port,host=host)
        return conn
    except Exception as e:
        print e
        sys.exit(1)

def connect_to_postgres():
    db = "ms17010"
    username = "stephen"    
    try:
        conn = ps2.connect(user=username, database=db)
        return conn
    except Exception as e:
        print e
        sys.exit(1)

def connect_to_geode():
    scp = CP.ConfigParser()
    section = "database"
    conf = '/etc/geode/settings.conf'

    scp.read(conf)

    username = scp.get(section, "username")
    password = scp.get(section, "password")
    host = scp.get(section, "host")
    database = scp.get(section, "database")
    port = '5432'
    try:
        conn = ps2.connect(user=username, password=password, host=host, database=database, port=port)
        return conn
    except Exception as e:
        print e
        sys.exit(1)

def search_splunk(conn, search):
    jobs = conn.jobs
    kwargs = {'exec_mode': 'blocking'}
    
    job = jobs.create(search, **kwargs)
    rs = job.results(count=0)

    for result in results.ResultsReader(io.BufferedReader(ResponseReaderWrapper(rs))):
        yield result
    job.cancel()

def do_lookups(lookup_dict):
    """We need to scan the IP
    See if its vulnerable
    if it is, see if we already found it
    if we did, update time
    if we didn't, insert
    """
    ips = ""
    for ip in lookup_dict.itervalues():
        ips += ip + ' '
    output = subprocess.check_output("nmap -p445 -Pn --script smb-vuln-ms17-010.nse %s" % ips, shell=True)
    vulnerable_ips = []
    #output = subprocess.check_output("nmap -p445 -Pn --script smb-vuln-ms17-010.nse %s" % '137.99.69.111', shell=True)
    output = output.split('\n') 
    for line in output:
        ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)
        if ip:
            current_ip = ip[0]
        else:
            if 'State: VULNERABLE' in line:
                vulnerable_ips.append(current_ip)
    return vulnerable_ips

def do_geode_lookup(geode_cur, mac):
    query = '''SELECT netid, hostname FROM sediment WHERE mac = (%s) and netid IS NOT NULL and hostname IS NOT NULL ORDER BY stop DESC LIMIT 1;'''
    data = (mac,)
    geode_cur.execute(query, data)
    result = geode_cur.fetchall()
    print result
    if result:
        return result[0][0], result[0][1]
    else:
        return None, None


def send_email(first_name, email, mac, ip):
    # First do a geode lookup on mac
    conf_file = "mass_mail_creds"
    parser = CP.RawConfigParser()
    parser.read(conf_file)
    smtpObj = smtplib.SMTP('massmail.uconn.edu', 587)
    smtpObj.ehlo()
    smtpObj.starttls()
    smtpObj.ehlo()
    smtpObj.login(parser.get("senior_design", "user"), parser.get("senior_design", "pass"))

    fromaddr = "security@uconn.edu"
    toaddr = ["stephen.lincoln@uconn.edu"]
    
    subject = "Wannacry pls fix"
    body = "Srsly guys"

    msg = "Subject: {}\n\n{}".format(subject, body)
    smtpObj.sendmail(fromaddr, toaddr, msg)
    smtpObj.quit()

    print "Sent mail"

def do_LDAP_lookup(netid):
    ldap = ldaplib.LDAP()
    f = ldap.generate_filter({'netid':netid})
    result = ldap.subtree_search(f)[0][1]
    first_name = result['givenName'][0]
    email = result['mail'][0]

    print first_name
    print email

    first_name = "FOo"
    email = "foo.bar@uconn.edu"

    return first_name, email

def main():
    
    spl_conn = connect_to_splunk()
    psql_conn = connect_to_postgres()
    geode_conn = connect_to_geode()
    psql_conn.autocommit=True
    psql_cur = psql_conn.cursor()
    geode_cur = geode_conn.cursor()

    
    search = '''search sourcetype=dhcp DHCPACK NOT client_ip=10.* AND NOT hostname=*iPhone* AND NOT hostname=*mac* AND NOT hostname=*android* AND NOT hostname=*iPad* earliest=-1m | dedup client_ip | fields _time, client_ip, mac'''
    while True:
        lookup_dict = {}
        #data_file = open('stats.txt', 'a')
        for r in search_splunk(spl_conn, search):
            mac = r.get('mac')
            ip = r.get('client_ip')
            sql = '''SELECT mac FROM vulnerable WHERE mac = (%s);'''
            data = (mac,)
            psql_cur.execute(sql, data)
            results = psql_cur.fetchone()
            last_time = r.get('_time')
            if results is None:
                lookup_dict[mac] = ip
        vulnerable_ips = do_lookups(lookup_dict)
        #data_file.write("{0}, {1}, {2}".format(last_time, len(lookup_dict), results_count))
        #data_file.close()
        for k in lookup_dict.keys():
            if k is not None:
                if lookup_dict[k] in vulnerable_ips:
                    data = (k, lookup_dict[k], "True")
                    netid, hostname = do_geode_lookup(geode_cur, k)
                    print "Looking up {0}".format(netid)
                    if netid is not None and hostname is not None:
                        first_name, email = do_LDAP_lookup(netid)
                        send_email(first_name, email, mac, hostname)
                else:
                    data = (k, lookup_dict[k], "False")
                query = '''INSERT INTO vulnerable (mac, last_ip, vulnerable) VALUES (%s, %s, %s);'''
                psql_cur.execute(query, data)
if __name__ == "__main__":
    main()
