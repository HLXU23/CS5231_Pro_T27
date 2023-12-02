# Author: Xu Hailing

import sys
import re

rule_type = ['syscall', 'file']
rule_dict = {}

class rule:
    def __init__(self, tag, typ, con):
        self.tag = tag
        self.typ = rule_type[typ] # 0 for syscall rule, 1 for file monitoring rule
        self.con = con[:-1] # delete final "\n"
        self.file = []
        rule_dict[tag] = self
        
    def __str__(self) -> str:
        return ','.join([self.tag, \
                        self.typ, \
                        self.con])

    def add_file(self, file_path):
        self.file.append(file_path)

def read_rule(rule_name):
    
    # load rule file
    rule_path = '../rules/audit-' + rule_name + '.conf'
    rule_f = open(rule_path, mode = 'r')
    index = 0
    tag = ""
    for rule_line in rule_f.readlines():
        if not rule_line:
            continue
        new_tag = re.findall('-k\s(\w*)', rule_line)
        if new_tag: # find new rule
            file_path = re.findall('-w\s(\S*)', rule_line)
            if not tag == new_tag[0]: # find new rule tag
                tag = new_tag[0]
                if file_path:
                    rule(tag, 1, rule_line)
                    rule_dict[tag].add_file(file_path)
                else:
                    rule(tag, 0, rule_line)
            elif tag: # find old rule tag
                if file_path:
                    rule_dict[tag].add_file(file_path)
    rule_f.close()
    
    # write output file
    output_path = '../analysis/read_' + rule_name + '.txt'
    output_f = open(output_path, mode = "w")
    print('Reading rules')
    for item in rule_dict:
        output_f.write(str(rule_dict[item]) + '\n')
    output_f.close()

def main():
    if len(sys.argv) < 2:
        exit("Please define rule name")
    rule_name = sys.argv[1]
    read_rule(sys.argv[1])

if __name__ == '__main__':
    main()

