# Author: Xu Hailing

import json
import sys
import re
from read_rule import *

log_dict = {}
file_dict = {'0': 'stdin', \
             '1': 'stdout', \
             '2': 'stderr'}
time_statis = {}
tag_statis = {}
file_statis = {}

class log:
    def __init__(self, seq, timestamp, tag, syscall, executable, pid):
        self.seq = seq
        self.timestamp = timestamp
        self.tag = tag
        self.syscall = syscall
        self.executable = executable
        self.pid = pid
        self.info = ''
        log_dict[seq] = self

    def __str__(self) -> str:
        return ','.join([str(self.seq), \
                         self.timestamp, \
                         self.tag, \
                         self.syscall, \
                         self.executable, \
                         str(self.pid), \
                         self.info])

    def add_info(self, info):
        self.info += info


def read_log(rule_name, log_name):

    # load rule file
    read_rule(rule_name)

    # load log file
    log_path = "../logs/auditbeat-" + log_name + ".ndjson"
    log_f = open(log_path, mode = 'r')
    print('Reading logs')
    accessed_file = ''
    for log_ndjson in log_f.readlines():
        log_line = json.loads(log_ndjson)
        try:
            timestamp = log_line['@timestamp'][11:-1]
            seq = log_line['auditd']['sequence']
            tag = log_line['tags'][0]
            syscall = log_line['auditd']['data']['syscall']
            process_name = log_line['process']['name']
            process_executable = log_line['process']['executable']
            pid = log_line['process']['pid']
            log(seq, timestamp, tag, syscall, process_executable, pid)
            try:
                tag_statis[tag + '(' + syscall + ')'] = tag_statis[tag + '(' + syscall + ')'] + 1
            except:
                tag_statis[tag + '(' + syscall + ')'] = 1
            try:
                time_statis[timestamp] = time_statis[timestamp] + 1
            except:
                time_statis[timestamp] = 1
        except KeyError:
            continue

        if rule_dict[tag].typ == 'syscall':
            if tag in ['file_access']:
                if syscall in ['open','openat']:
                    try:
                        file_path = log_line['file']['path']
                        data_exit = log_line['auditd']['data']['a0']
                        file_dict[data_exit] = file_path
                        accessed_file = file_path
                        log_dict[seq].add_info(file_path)
                        try:
                            file_statis[accessed_file] += 1
                        except:
                            file_statis[accessed_file] = 1
                    except KeyError:
                        continue

            if tag in ['exec']:
                if syscall in ['execve']:
                    try:
                        process_args = log_line['process']['args']
                        for arg in process_args:
                            if 'program' in arg:
                                log_dict[seq].add_info(arg + ',')
                            try:
                                file_statis[arg] += 1
                            except:
                                file_statis[arg] = 1
                    except KeyError:
                        continue


            if tag in ['curl']:
                if syscall in ['open', 'openat']:
                    try:
                        file_path = log_line['file']['path']
                        data_exit = log_line['auditd']['data']['a0']
                        file_dict[data_exit] = file_path
                        accessed_file = file_path
                        log_dict[seq].add_info(file_path)
                        try:
                            file_statis[accessed_file] += 1
                        except:
                            file_statis[accessed_file] = 1
                    except KeyError:
                        continue
                        
                    if len(paths) > 1:
                        name_type = paths[1]['nametype']
                        log_dict[seq].add_info(name_type + ',')
                        name = paths[1]['name']
                        log_dict[seq].add_info(name)
                
                if syscall in ['sendto', 'recvfrom']:
                    try:
                        data_exit = log_line['auditd']['data']['exit']
                    except KeyError:
                        continue

            if tag in ['externel']:
                if syscall in ['connect']:
                    try:
                        destination = log_line['destination']
                        socket = log_line['auditd']['data']['socket']
                        result = log_line['auditd']['result']
                    except KeyError:
                        continue

                if syscall in ['bind']:
                    try:
                        destination = log_line['destination']
                        socket = log_line['auditd']['data']['socket']
                        result = log_line['auditd']['result']
                        a0 = data['auditd']['data']['a0']
                        acceseed_file = file_dict.get(a0, '?')
                        try:
                            file_statis[accessed_file] += 1
                        except:
                            file_statis[accessed_file] = 1
                    except KeyError:
                        continue

            if 'socket' in tag:
                try:
                    result = log_line['auditd']['result']
                    data_exit = log_line['auditd']['data']['exit']
                    accessed_file = file_dict.get(data_exit, '?')
                    try:
                        file_statis[accessed_file] += 1
                    except:
                        file_statis[accessed_file] = 1
                except KeyError:
                    continue


            if 'program11' in process_name or 'program11' in process_executable:
                print(log_dict[seq])

    log_f.close()

    # write output file
    output_path ='../analysis/' + log_name + '_read_log.txt'
    output_f = open(output_path, mode = 'w')
    for item in log_dict:
        output_f.write(str(log_dict[item]) + '\n')
    output_f.close()

    # write statistic file
    statis_time_path = '../analysis/' + log_name + '_statis_time.txt'
    statis_time_f = open(statis_time_path, mode = 'w')
    for item in time_statis:
        statis_time_f.write(item + ',' + str(time_statis[item]) + '\n')
    statis_time_f.close()
    
    statis_tag_path = '../analysis/' + log_name + '_statis_tag.txt'
    statis_tag_f = open(statis_tag_path, mode = 'w')
    for item in tag_statis:
        statis_tag_f.write(item + ',' + str(tag_statis[item]) + '\n')
    statis_tag_f.close()

    statis_file_path = '../analysis/' + log_name + '_statis_file.txt'
    statis_file_f = open(statis_file_path, mode = 'w')
    for item in file_statis:
        statis_file_f.write(item + ',' + str(file_statis[item]) + '\n')
    statis_file_f.close()

def main():
    if len(sys.argv) < 3:
        exit("Please define rule name and log name")
    rule_name = sys.argv[1]
    log_name = sys.argv[2]
    read_log(rule_name, log_name)

if __name__ == '__main__':
    main()
