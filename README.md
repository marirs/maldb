maldb
=====

Feeds of malware related IP or domains

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


