#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Description:
    Get list of malware related domains and ip addresses from ZeusTracker, MalwareDomainList,
    GameOverZeus (goz),CyberCrimeTracker

    And gives a FINAL json output. It can be consumed in environments with a SIEM or splunk etc.,
    to analyse or correlate the logs for any/potential suspicious activities

Requirements:
    Python 2.7.x
    BeautifulSoup module - for web scraping (pip install beautifulsoup)

Usage:
$ ./maldb.py [options]

    Options:
      --version                     show program's version number and exit
      -h, --help                    show this help message and exit
      -q, --quiet                   do not display debug messages
      --src=complete                which source to query (rss, complete) default is complete
      -r both, --result-set=both    result-set: IP or HOSTS or BOTH (There are 2 types of results
                                    1. IP addresses - can be used for block lists or scan IDS/FW logs
                                    2. Domain TLDS - can be used to scan web proxy logs
                                    3. OR Both of them (default)
                                    )
      -o csv, --output=csv          output type: csv or json (Gives a JSON or CSV output) default is CSV
      -d 7, --days=7                last no. of days to query ($Now - days) default is 7 days

Examples:
    query rss feeds of MDL and rest for the last 7 days (default)
    ./maldb.py

    query rss feeds of MDL and rest for the last 5 days
    ./maldb.py --mdl=rss -d=5

    query the complete csv of MDL and rest for the last 7 days
    ./maldb.py --mdl=complete

    do not output the debug messages
    ./maldb.py -q --mdl=complete

"""
from operator import itemgetter
from xml.dom import minidom
from collections import defaultdict
from textwrap import dedent
from BeautifulSoup import BeautifulSoup
from optparse import OptionParser
import logging, re, sys, io
from StringIO import StringIO
import requests, json
import csv, datetime, threading


__author__ = 'Sriram G'
__version__ = '1'
__license__ = 'GPLv3'


# User Agent String
UA = "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36"
"""
mal_ips/mal_domains is a dynamic list that will store malicious ips associated to their
malware names, which can be used to have an update of current malicious ip's
"""
result_mal_ips = []
result_mal_domains = []

src = "rss"
pastdays = 7

# Setup logging
quiet_mode = False
logger = logging.getLogger('maldb')
logger.setLevel(logging.DEBUG)
logging.basicConfig(format='[%(levelname)-7s] %(asctime)s | %(message)s', datefmt='%I:%M:%S %p')


#
# begin of functions
#
def unique_list(l=[]):
    """
    make a list of unique values
    """
    result = list()
    map(lambda x: not x in result and result.append(x), l)
    return result


def print_csv(csv_content):
    """
    Prints CSV file to standard output.
    If csv_mode is set to false, prints a tab separated output
    returns: none
    """
    pCSV = csv.writer(sys.stdout)
    [pCSV.writerow(row) for row in csv_content]


def print_json(l_content):
    """
    json output
    """
    json_output = defaultdict(list)
    t = defaultdict(list)
    for r in l_content:

        date_added  = ','.join(r).split(',')[0].strip()
        malware_type = ','.join(r).split(',')[1].strip()
        host = ','.join(r).split(',')[2].strip()
        source = ','.join(r).split(',')[3].strip()
        json_output[malware_type].append({'date': date_added, 'source': source, 'host-C2': host})

    print json.dumps([{'name': k, 'value': v} for k,v in json_output.items()], indent=2)


def touchCSV(fn, csvList, append=False):
    """
    function to write a list as csv to a file
    returns: none
    """
    mode = ("a+b" if append else "wb")
    with open(fn, mode) as f:
        writer = csv.writer(f)
        writer.writerows(csvList)


def zeustracker():
    """
    get info from zeus tracker
    stores: Zeus IP list, Zeus domain list
    returns: none
    other urls:
        https://zeustracker.abuse.ch/rss.php
        https://zeustracker.abuse.ch/monitor.php?urlfeed=binaries
        https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist
        https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist
        https://zeustracker.abuse.ch/monitor.php?filter=all
    """
    global result_mal_domains, result_mal_ips
    zeus_ip_blocklist = []
    zeus_domain_blocklist = []
    title = desc = ""
    headers = {'User-Agent': UA}
    query_date = datetime.datetime.strptime(str(datetime.date.today() - datetime.timedelta(days=pastdays)), "%Y-%m-%d")
    if "rss" in src:
        url = "https://zeustracker.abuse.ch/rss.php"
        try:
            logger.debug("zeustracker() rss db")
            response = requests.get(url, headers=headers)
            xml_response = response.text
            xml_doc = minidom.parseString(xml_response)
            items = xml_doc.getElementsByTagName('item')
            for item in items:
                """
                <title>ipaddress (Y-m-d time)</title>
                <link>
                <description>Host: hostname, IP address: ipaddress, SBL: sbl, status: online/offline, level: , Malware: name, AS: number, country: ISO-2</description>
                <guid>
                """
                title = " ".join(t.nodeValue for t in item.getElementsByTagName("title")[0].childNodes if t.nodeType == t.TEXT_NODE)
                desc = " ".join(t.nodeValue for t in item.getElementsByTagName("description")[0].childNodes if t.nodeType == t.TEXT_NODE)
                details = str(desc).split(',')
                abusech_dt = datetime.datetime.strptime(str(title.split(' (',1)[1].split(' ',1)[0]), "%Y-%m-%d")
                if abusech_dt > query_date:
                    d = str(details[5]).partition(': ')[2].split('/',1)[0].strip().replace(',','-')
                    ips = str(details[1]).partition(': ')[2].split('/',1)[0].strip()
                    domains = str(details[0]).partition(': ')[2].split('/',1)[0].strip()

                    if not re.match(r'^\s*$|-', ips) and ips not in zeus_ip_blocklist:
                        zeus_ip_blocklist.append([abusech_dt.strftime('%Y-%m-%d'),d,ips,'abuse.ch'])
                    if not re.match(r'^\s*$|-', domains) and domains not in zeus_domain_blocklist:
                        zeus_domain_blocklist.append([abusech_dt.strftime('%Y-%m-%d'),d,domains,'abuse.ch'])
        except Exception, err:
            logger.error("Error retrieving ZeusTracker RSS results: %s" % err)

    elif "complete" in src or "updates" in src:
        url = "https://zeustracker.abuse.ch/monitor.php" # ?filter=all if you need the entire db
        try:
            logger.debug("zeustracker() complete db")
            response = requests.get(url, headers=headers)
            html = BeautifulSoup(response.text)

            the_table = html.body.findAll("table", {"class": "table"})
            for row in the_table[1].findAll("tr")[1:]:
                cells = row.findAll("td")
                dt = datetime.datetime.strptime(str(cells[0].find(text=True)), "%Y-%m-%d")
                if dt > query_date:
                    ips = str(cells[3].find(text=True)).strip()
                    ips = ips if not re.match(r'^\s*$|-|None|FastFlux Botnet', ips) else ''
                    domains = str(cells[2].find(text=True)).strip()
                    d = str(cells[1].find(text=True)).strip()

                    if not re.match(r'^\s*$|-', ips) and ips not in zeus_ip_blocklist:
                        zeus_ip_blocklist.append([dt.strftime('%Y-%m-%d'),d,ips,'abuse.ch'])
                    if not re.match(r'^\s*$|-', domains) and domains not in zeus_domain_blocklist:
                        zeus_domain_blocklist.append([dt.strftime('%Y-%m-%d'),d,domains,'abuse.ch'])
        except Exception, err:
            logger.error("Error retrieving ZeusTracker Complete db: %s" % err)


    result_mal_ips += (zeus_ip_blocklist)
    result_mal_domains += (zeus_domain_blocklist)


def goz():
    """
    GameOver Zeus
    stores: list of gameover zeus domains
    returns: none
    """
    global result_mal_ips, result_mal_domains
    url = "http://osint.bambenekconsulting.com/feeds/goz-domlist.txt"
    headers = {'User-Agent': UA}
    goz_domains = []
    try:
        logger.debug("goz()")
        response = requests.get(url, headers=headers)
        csv_response = csv.reader(filter(lambda x: not re.match(r'^\s*$|\#', x), str(response.text.encode('ascii','ignore')).split('\n')))
        for row in csv_response:
            domains = row[0]
            dt = datetime.datetime.strptime(str(row[2]).split(' ')[0].strip(), "%Y-%m-%d")
            if not re.match(r'^\s*$|-', domains) and domains not in goz_domains:
                goz_domains.append([dt.strftime('%Y-%m-%d'),'GoZ',domains,'osint.bambenekconsulting'])

    except Exception, err:
        logger.error("Error retrieving goz() results: %s" % err)

    result_mal_domains += (goz_domains)


def mdl():
    """
    malware domain list
    input:
        src = source type
            can be rss, complete, updates
        pastdays = Now - $howlong
    stores: csv of malware ips, csv of malware domains
    returns: none

    available @ mdl are:
        http://www.malwaredomainlist.com/mdlcsv.php
        complete database in csv format

        http://www.malwaredomainlist.com/updatescsv.php
        updates in csv format

        http://www.malwaredomainlist.com/hostslist/mdl.xml
        RSS feed of url updates

        http://www.malwaredomainlist.com/hostslist/zeus.xml
        RSS feed of zbot/zeus url updates

        http://www.malwaredomainlist.com/zeuscsv.php
        ZeuS urls in csv format

        http://www.malwaredomainlist.com/hostslist/hosts.txt
        hosts.txt an be used as a block list

        http://www.malwaredomainlist.com/hostslist/delisted.txt
        sites which are offline or have been cleaned

        http://www.malwaredomainlist.com/hostslist/yesterday.php
        all new database entries from yesterday (all db fields)

        http://www.malwaredomainlist.com/hostslist/yesterday_urls.php
        all new urls from yesterday  (url only)

        http://www.malwaredomainlist.com/hostslist/ip.txt
        list of active ip addresses
    """
    global result_mal_ips, result_mal_domains
    query_date = datetime.datetime.strptime(str(datetime.date.today() - datetime.timedelta(days=pastdays)), "%Y-%m-%d")
    headers = {'User-Agent': UA}
    mdl_ip = []
    mdl_domains = []
    if "rss" in src:
        """
        getting rss feeds from mdl (xml format)
        """
        url = "http://www.malwaredomainlist.com/hostslist/mdl.xml"
        title = desc = ""
        logger.debug("mdl rss feeds")
        try:
            response = requests.get(url, headers=headers)
            xml_response = response.text
            xml_doc = minidom.parseString(xml_response)
            items = xml_doc.getElementsByTagName('item')
            #print items[0].toxml()
            for item in items:
                """
                tags available are:
                <title>domain name (date_time)</title>
                <link>
                <description>host: , ip address: , asn: , country: , description</description>
                <guid>
                """
                title = " ".join(t.nodeValue for t in item.getElementsByTagName("title")[0].childNodes if t.nodeType == t.TEXT_NODE)
                desc = " ".join(t.nodeValue for t in item.getElementsByTagName("description")[0].childNodes if t.nodeType == t.TEXT_NODE)
                details = str(desc).split(',', 4)
                mdl_dt = datetime.datetime.strptime(str(title.split(' (',1)[1].split('_',1)[0]), "%Y/%m/%d")
                # check to see if date is greater than the query_date
                # so that we get only the last number of days we want
                if mdl_dt > query_date:
                    d = str(details[4]).partition(': ')[2].split('/',1)[0].strip().replace(',','-')
                    ips = str(details[1]).partition(': ')[2].split('/',1)[0].strip()
                    domains = str(details[0]).partition(': ')[2].split('/',1)[0].strip()

                    if not re.match(r'^\s*$|-', ips) and ips not in mdl_ip:
                        mdl_ip.append([mdl_dt.strftime('%Y-%m-%d'),d,ips,'MalwareDomainList'])
                    if not re.match(r'^\s*$|-', domains) and domains not in mdl_domains:
                        mdl_domains.append([mdl_dt.strftime('%Y-%m-%d'),d,domains,'MalwareDomainList'])
        except Exception, err:
            logger.error("Error retrieving MDL rss results: %s" % err)

    elif "complete" in src or "updates" in src:
        """
        getting the complete/updates db from mdl (csv format)
        filtered = filter(lambda x: not re.match(r'^\s*$', x), variable)
        """
        if "complete" in src:  url = "http://www.malwaredomainlist.com/mdlcsv.php"
        elif "updates" in src: url = "http://www.malwaredomainlist.com/updatescsv.php"
        desc = ips = domains = ""
        logger.debug("mdl %s csv" % src)
        try:
            response = requests.get(url, headers=headers)
            csv_response = csv.reader(filter(lambda x: not re.match(r'^\s*$', x), str(response.text.encode('ascii','ignore')).split('\n')))
            for row in csv_response:
                mdl_dt = datetime.datetime.strptime(str(row[0].split('_',1)[0]), "%Y/%m/%d")
                # check to see if date is greater than the query_date
                # so that we get only the last number of days we want
                if mdl_dt > query_date:
                    desc = str(row[4]).replace(',', '-')
                    ips = str(row[2]).split('/',1)[0].strip()
                    domains = str(row[1]).split('/',1)[0].strip()

                    if not re.match(r'^\s*$|-', ips) and ips not in mdl_ip:
                        mdl_ip.append([mdl_dt.strftime('%Y-%m-%d'),desc,ips,'MalwareDomainList'])
                    if not re.match(r'^\s*$|-', domains) and domains not in mdl_domains:
                        mdl_domains.append([mdl_dt.strftime('%Y-%m-%d'),desc,domains,'MalwareDomainList'])
        except Exception, err:
            logger.error("Error retrieving MDL %s csv results: %s" % (src, err))


    result_mal_ips += (mdl_ip)
    result_mal_domains += (mdl_domains)


def cybercrime_tracker():
    """
    Gets results from CyberCrime-tracker.net
    input: past how long
    stores: list of ip's and domains
    returns: none
    """
    global result_mal_ips, result_mal_domains
    url = "http://cybercrime-tracker.net/index.php?s=0&m=200"
    query_date = datetime.datetime.strptime(str(datetime.date.today() - datetime.timedelta(days=pastdays)), "%Y-%m-%d")
    headers = {'User-Agent': UA}
    l_ccdomains = []
    l_ccips = []
    try:
        logger.debug("CyberCrimeTracker()")
        response = requests.get(url, headers=headers)
        html = BeautifulSoup(response.text)
        the_table = html.body.findAll("table", {"class": "ExploitTable"})
        for row in the_table[0].findAll("tr")[1:]:
            cells = row.findAll("td")
            dt = datetime.datetime.strptime(str(cells[0].find(text=True)), "%d-%m-%Y")
            if dt > query_date:
                ips = str(cells[2].find(text=True)).strip()
                ips = ips if not re.match(r'^\s*$|-|None|FastFlux Botnet', ips) else ''
                domains = str(cells[1].find(text=True)).split('/',1)[0].strip()
                d = str(cells[3].find(text=True)).strip()

                #csv
                if not re.match(r'^\s*$|-', ips) and ips not in l_ccips:
                    l_ccips.append([dt.strftime('%Y-%m-%d'),d,ips,'CyberCrime-Tracker'])
                if not re.match(r'^\s*$|-', domains) and domains not in l_ccdomains:
                    l_ccdomains.append([dt.strftime('%Y-%m-%d'),d,domains,'CyberCrime-Tracker'])
    except Exception, err:
        logger.error("Error getting CyberCrimeTracker results: %s" % err)

    result_mal_domains += (l_ccdomains)
    result_mal_ips += (l_ccips)


class _tworker(threading.Thread):
    """
    threading class for certain functions that
    returns value. can be used with functions that don't return value as well
    """
    def __init__(self, *args, **kwargs):
        super(_tworker, self).__init__(*args, **kwargs)

        self._return = None

    def run(self):
        if self._Thread__target is not None:
            self._return = self._Thread__target(*self._Thread__args, **self._Thread__kwargs)

    def join(self, *args, **kwargs):
        super(_tworker, self).join(*args, **kwargs)

        return self._return


def main():
    """
    main function
    """
    global result_mal_domains, result_mal_ips, quiet_mode, src, pastdays
    parser = OptionParser()
    output = "csv"
    thread_list = []
    merged_results_csv = results_ips_csv = results_domains_csv = ""
    results = "both"
    parser = OptionParser(usage="usage: %prog [options] ",version="maldb v1")
    parser.add_option("-q","--quiet",action="store_true",dest="quiet_mode",help="do not display debug messages",default=False)
    parser.add_option("--src", dest="srcType",help="which source to query (rss, complete, updates)", metavar="complete",default="complete")
    parser.add_option("-r","--result-set", dest="results",help="result-set: IP or HOSTS or BOTH", metavar="both",default="both")
    parser.add_option("-o","--output", dest="output",help="output type: csv or json", metavar="csv",default="csv")
    parser.add_option("-d","--days", dest="pastdays",help="no. of days to query", metavar="7",default="7")

    (options, args) = parser.parse_args()
    quiet_mode = options.quiet_mode
    output = options.output
    src = options.srcType
    results = options.results
    pastdays = int(str(options.pastdays).replace('=',''))
    # set logging level
    if quiet_mode: logger.setLevel(logging.INFO)
    print parser.version

    worker_funs = ['zeustracker','goz','cybercrime_tracker','mdl'] # functions that goes into threads
    thread = _tworker(target=zeustracker)
    thread.start()
    thread_list.append(thread)
    thread = _tworker(target=goz)
    thread.start()
    thread_list.append(thread)
    thread = _tworker(target=cybercrime_tracker)
    thread.start()
    thread_list.append(thread)
    thread = _tworker(target=mdl)
    thread.start()
    thread_list.append(thread)
    """
    Yield for threads to finish
    """
    for t in thread_list:
        try:
            t.join()
        except TypeError:
            logger.info("__%s: completed.." % str(t))

    #sort the results
    result_mal_domains = sorted(result_mal_domains, key=itemgetter(0,3))
    result_mal_ips = sorted(result_mal_ips, key=itemgetter(0,3))

    # if merged results
    merged_results = result_mal_ips + result_mal_domains
    merged_results = sorted(merged_results, key=itemgetter(0,3))
    header_string = dedent("""
    ##
    ## Past %d days data
    ##
    ## List of ip's and domains found to be malicious
    ## Sources: MDL,CC-T,GOZ,ZeusTracker and Own Research
    ## License: GPL v3
    ##
    ## While all care is taken on the research, I take no responsibility
    ## if the data provided here causes any sought of inconvenience
    ##
    ## Last generated: %s
    ##
    """) % (pastdays,datetime.datetime.today().strftime('%Y-%m-%d'))
    print header_string

    if "json" in output:
        if "hosts" in results: print_json(result_mal_domains)
        elif "ip" in results: print_json(result_mal_ips)
        else: print_json(merged_results)
    else:
        print "date added, malware type, host, source"
        if "hosts" in results: print_csv(result_mal_domains)
        elif "ip" in results: print_csv(result_mal_ips)
        else: print_csv(merged_results)


if __name__ == '__main__':
    main()



"""
<< EOF
"""
