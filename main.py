#!/usr/bin/env python

import glob
import multiprocessing
import re
import os, sys
import getopt
import time
import sqlite3
import datetime


monthnames = { 1: 'Jan', 2: 'Feb', 3: 'Mar', 4: 'Apr', 5: 'May', 6: 'Jun', 7: 'Jul', 8: 'Aug', 9: 'Sep', 10: 'Oct', 11: 'Nov', 12: 'Dec' }
monthreverse = { 'Jan': 1, 'Feb': 2, 'Mar': 3, 'Arp': 4, 'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12 }

"""
processLog reads chunks of the maillog, parses its lines and sum into a data structure
"""
def processLog(filename, start=0, stop=0, chunk=0, month=0):
    if start == 0 and stop == 0:
        return
    else:
        days = {}
        for i in range(1, 32):
            days[str(i)] = {
                    'pclean': 0, 'pspam': 0, 'bspam': 0,
                    'lmtps': 0, 'lmtpq': 0, 'lmtpf': 0,
                    'smtpincoming': 0, 'smtprelay': 0, 'smtpconnect': 0,
                    'greylisted': 0,
                    'domainnotfound': 0,
                    'nofqdn': 0,
                    'userunknown': 0,
                    'relaydenied': 0,
                    'sizelimit': 0,
                    'notownedbyuser': 0,
                    'invalidmethod': 0,
                    'conntimeout': 0,
                    'rblsite': {
                        'zen.spamhaus.org': 0,
                        'korea.services.net': 0,
                        'cbl.abuseat.org': 0,
                        'bl.spamcop.net': 0,
                        }
                    }

        monthname = monthnames[month]

        """ Patterns """
        amavisre = re.compile(r'%s+\s+(\d+).*amavis\[\d+\]: \(\d+\-\d+\) (\w+) (\w+)' % monthname)
        lmtpre = re.compile(r'^%s+\s+(\d+).*dovecot: lmtp.*sieve: msgid=<.*>:.*(stored mail into mailbox|failed to store into mailbox|forwarded to)(.*)' % monthname)
        qmgrre = re.compile(r'%s+\s+(\d+).*postfix\/[n]*qmgr.*from=<[\w\-\.@]+>' % monthname)
        relayre = re.compile(r'%s+\s+(\d+).*postfix\/smtp\[.*relay=(?!127.0.0.1|150.163.|none)' % monthname)
        smtpconre = re.compile(r'%s+\s+(\d+).*postfix\/smtpd\[.* connect from (?!unknown\[127\.0\.\0\.1\])' % monthname)
        greylistedre = re.compile(r'^%s+\s+(\d+).*postfix\/smtpd\[\d+\]: NOQUEUE: reject: RCPT from ([\w\.\-]+\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]): .*Greylisted' % monthname)
        domainnotfoundre = re.compile(r'%s+\s+(\d+).*postfix\/smtpd\[\d+\]: NOQUEUE: reject: RCPT from ([\w\.\-]+\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]): .*(Domain not found|Host or domain name not found)' % monthname)
        nofqdnre = re.compile(r'^%s+\s+(\d+).*postfix\/smtpd\[\d+\]: NOQUEUE: reject: RCPT from ([\w\.\-]+\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]): 450 4.5.2.*need fully-qualified address' % monthname)
        userunknownre = re.compile(r'^%s+\s+(\d+).*postfix\/smtpd\[\d+\]: NOQUEUE: reject: RCPT from ([\w\.\-]+\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]): .*(User unknown in .* table|User doesn\'t exist)' % monthname)
        relaydeniedre = re.compile(r'^%s+\s+(\d+).*postfix\/smtpd\[\d+\]: NOQUEUE: reject: RCPT from ([\w\.\-]+\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]): .*Access denied' % monthname)
        sizelimitre = re.compile(r'^%s+\s+(\d+).*postfix\/smtpd\[\d+\]: NOQUEUE: reject: \w+ from ([\w\.\-]+\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]): .*Message size exceeds fixed limit' % monthname)
        notowneduserre = re.compile(r'^%s+\s+(\d+).*postfix\/smtpd\[\d+\]: NOQUEUE: reject: RCPT from ([\w\.\-]+\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]): .*not owned by user' % monthname)
        invalidmethodre = re.compile(r'^%s+\s(\d+).*postfix\/smtpd\[\d+\]: NOQUEUE: reject: RCPT from ([\w\.\-]+\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]): .*Improper use of SMTP command pipelining' % monthname)
        conntimeoutre = re.compile(r'^%s+\s+(\d+).*postfix\/smtpd\[\d+\]: NOQUEUE: reject: RCPT from ([\w\.\-]+\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]): .*Connection timed out' % monthname)
        rblre = re.compile(r'^%s+\s+(\d+).*postfix\/smtpd\[\d+\]: NOQUEUE: reject: RCPT from ([\w\.\-]+\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]): 450 4.7.1 Service unavailable; Client host \[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\] blocked using ([\w\.@]+)' % monthname)

        sys.stdout.write('%d...' % chunk)
        sys.stdout.flush()

        with open(filename, 'r') as l:
            l.seek(start)
            """ Read just the chunk """
            for line in l.read(stop - start).splitlines():
                m = rblre.match(line)
                if m:
                    days[m.group(1)]['rblsite'][m.group(3)] += 1
                    continue
                m = amavisre.match(line)
                if m:
                    if m.group(2) == 'Passed' and m.group(3) == 'CLEAN':
                        days[m.group(1)]['pclean'] += 1
                    elif m.group(2) == 'Passed' and m.group(3) == 'SPAM':
                        days[m.group(1)]['pspam'] += 1
                    elif m.group(2) == 'Blocked' and m.group(3) == 'SPAM':
                        days[m.group(1)]['bspam'] += 1
                    continue
                m = lmtpre.match(line)
                if m:
                    if 'stored mail into mailbox' in m.group(2):
                        days[m.group(1)]['lmtps'] += 1
                    elif 'failed to store into mailbox' in m.group(2) and 'Quota exceeded' in m.group(3):
                        days[m.group(1)]['lmtpq'] += 1
                    elif 'forwarded to' in m.group(2):
                        days[m.group(1)]['lmtpf'] += 1
                    continue
                m = qmgrre.match(line)
                if m:
                    days[m.group(1)]['smtpincoming'] += 1
                    continue
                m = relayre.match(line)
                if m:
                    days[m.group(1)]['smtprelay'] += 1
                    continue
                m = smtpconre.match(line)
                if m:
                    days[m.group(1)]['smtpconnect'] += 1
                    continue
                m = greylistedre.match(line)
                if m:
                    days[m.group(1)]['greylisted'] += 1
                    continue
                m = domainnotfoundre.match(line)
                if m:
                    days[m.group(1)]['domainnotfound'] += 1
                    continue
                m = nofqdnre.match(line)
                if m:
                    days[m.group(1)]['nofqdn'] += 1
                    continue
                m = userunknownre.match(line)
                if m:
                    days[m.group(1)]['userunknown'] += 1
                    continue
                m = relaydeniedre.match(line)
                if m:
                    days[m.group(1)]['relaydenied'] += 1
                    continue
                m = sizelimitre.match(line)
                if m:
                    days[m.group(1)]['sizelimit'] += 1
                    continue
                m = notowneduserre.match(line)
                if m:
                    days[m.group(1)]['notownedbyuser'] += 1
                    continue
                m = invalidmethodre.match(line)
                if m:
                    days[m.group(1)]['invalidmethod'] += 1
                    continue
                m = conntimeoutre.match(line)
                if m:
                    days[m.group(1)]['conntimeout'] += 1
                    continue

            return days

if __name__ == '__main__':
    month = 0
    logfile = './maillog'
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hm:', ['help', 'month='])
    except getopt.GetoptError as e:
        print str(e)
        sys.exit(2)

    for o, a in opts:
        if o in ('-m', '--month'):
            month = int(a)
        else:
            assert False, 'unhandled option'

    if month not in range(1, 13):
        print 'Invalid month'
        sys.exit(0)

    if logfile == None:
        print 'Inform the log file'
        sys.exit(0)

    filesize = os.path.getsize(logfile)
    split_size = 50*1024*1024
    procs = multiprocessing.cpu_count() - 1

    print 'Start processing \"%s\" file\n# CPU used: %d' % (logfile, procs)
    print 'The logfile will be splitted in %d chunks' % (filesize // split_size)
    time.sleep(1)

    pool = multiprocessing.Pool(processes=procs)
    cursor = 0
    end = 0
    chunk = 0
    results = []

    print 'Processing chunks'
    if filesize > split_size:
        with open('maillog', 'r') as l:
            while end != filesize:
                if cursor + split_size > filesize:
                    end = filesize
                else:
                    end = cursor + split_size

                l.seek(end)
                a1 = l.readline()

                end = l.tell()
                a2 = l.readline()

                proc = pool.apply_async(processLog, args=[logfile, cursor, end, chunk, month])
                results.append(proc)

                cursor = end
                chunk += 1
            pool.close()
            pool.join()
    else:
        end = filesize
        proc = pool.apply_async(processLog, args=[logfile, cursor, end, chunk, month])
        results.append(proc)
        pool.close()
        pool.join()

    days = {}

    for proc in results:
        i = proc.get()
        for d in proc.get().keys():
            if d in days.keys():
                days[d]['pclean'] = days[d]['pclean'] + i[d]['pclean']
                days[d]['pspam'] = days[d]['pspam'] + i[d]['pspam']
                days[d]['bspam'] = days[d]['bspam'] + i[d]['bspam']
                days[d]['lmtps'] = days[d]['lmtps'] + i[d]['lmtps']
                days[d]['lmtpq'] = days[d]['lmtpq'] + i[d]['lmtpq']
                days[d]['lmtpf'] = days[d]['lmtpf'] + i[d]['lmtpf']
                days[d]['smtpincoming'] = days[d]['smtpincoming'] + i[d]['smtpincoming']
                days[d]['smtprelay'] = days[d]['smtprelay'] + i[d]['smtprelay']
                days[d]['smtpconnect'] = days[d]['smtpconnect'] + i[d]['smtpconnect']
                days[d]['greylisted'] = days[d]['greylisted'] + i[d]['greylisted']
                days[d]['domainnotfound'] = days[d]['domainnotfound'] + i[d]['domainnotfound']
                days[d]['nofqdn'] = days[d]['nofqdn'] + i[d]['nofqdn']
                days[d]['userunknown'] = days[d]['userunknown'] + i[d]['userunknown']
                days[d]['relaydenied'] = days[d]['relaydenied'] + i[d]['relaydenied']
                days[d]['sizelimit'] = days[d]['sizelimit'] + i[d]['sizelimit']
                days[d]['notownedbyuser'] = days[d]['notownedbyuser'] + i[d]['notownedbyuser']
                days[d]['invalidmethod'] = days[d]['invalidmethod'] + i[d]['invalidmethod']
                days[d]['conntimeout'] = days[d]['conntimeout'] + i[d]['conntimeout']
                days[d]['rblsite']['zen.spamhaus.org'] = days[d]['rblsite']['zen.spamhaus.org'] + i[d]['rblsite']['zen.spamhaus.org']
                days[d]['rblsite']['korea.services.net'] = days[d]['rblsite']['korea.services.net'] + i[d]['rblsite']['korea.services.net']
                days[d]['rblsite']['cbl.abuseat.org'] = days[d]['rblsite']['cbl.abuseat.org'] + i[d]['rblsite']['cbl.abuseat.org']
                days[d]['rblsite']['bl.spamcop.net'] = days[d]['rblsite']['bl.spamcop.net'] + i[d]['rblsite']['bl.spamcop.net']
            else:
                days[d] = i[d]

    with open('amavis.out', 'w') as o:
        o.write('%s,%s,%s,%s\n' % ('Day', 'Clean', 'Spam Passed', 'Spam Blocked'))
        for day in sorted(days, key=int):
            o.write('%s,%s,%s,%s\n' % (monthnames[month] + ' ' + day, days[day]['pclean'], days[day]['pspam'], days[day]['bspam']))
        o.close()
    with open('lmtp.out', 'w') as o:
        o.write('%s,%s,%s,%s\n' % ('Day', 'Saved', 'Quota', 'Forwarded'))
        for day in sorted(days, key=int):
            o.write('%s,%s,%s,%s\n' % (monthnames[month] + ' ' + day, days[day]['lmtps'], days[day]['lmtpq'], days[day]['lmtpf']))
        o.close()
    with open('smtp.out', 'w') as o:
        o.write('%s,%s,%s,%s\n' % ('Day', 'Incoming', 'Relay', 'Connect'))
        for day in sorted(days, key=int):
            o.write('%s,%s,%s,%s\n' % (monthnames[month] + ' ' + day, days[day]['smtpincoming'], days[day]['smtprelay'], days[day]['smtpconnect']))
        o.close()
    with open('policy.out', 'w') as o:
        o.write('%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' % ('Day', 'zen.spamhaus.org', 'korea.services.net', 'cbl.abuseat.org', 'bl.spamcop.net', 'RBL Total', 'Greylisted', 'Domain not found', 'No FQDN', 'User unknown',
            'Relay denied', 'Size limit', 'Not owned by user', 'Invalid Method', 'Timeout'))
        for day in sorted(days, key=int):
            o.write('%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' % (monthnames[month] + ' ' + day, days[day]['rblsite']['zen.spamhaus.org'], days[day]['rblsite']['korea.services.net'], days[day]['rblsite']['cbl.abuseat.org'], days[day]['rblsite']['bl.spamcop.net'], '', days[day]['greylisted'], days[day]['domainnotfound'], days[day]['nofqdn'], days[day]['userunknown'],
                days[day]['relaydenied'], days[day]['sizelimit'], days[day]['notownedbyuser'], days[day]['invalidmethod'], days[day]['conntimeout']))
        o.close()

    print '\nDone'
