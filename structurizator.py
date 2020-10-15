#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'PykhovaOlga'
import re
import pprint
import time
from datetime import datetime, date, time

class Main_parse():

# def main_1(config):
    def __init__(self):
        self.d_config = {}
        self.config = ''



    def set_config(self, config):
        self.config = config

    def d_parse_config_N(self, config):
        d_config = {}
        staff_list = re.split('[-]{7,}', config)  # change biggest string "config" to list
        # at the config name of bloks discriminate " #---------- echo header #-------- content "
        for num_list in range(0, len(staff_list)):
            rep = staff_list[num_list]
            temp = re.match("\s+echo", staff_list[num_list])  # header?
            if temp is not None:
                header = (staff_list[num_list]).replace('\n', '').replace('#', '')  # delete staff cymbol
                # print(header)
                if header not in d_config:
                    d_config[header] = staff_list[num_list + 1]  # dictionary "header": "content"
                    num_list += 1
                else:
                    header = header + ' DOUBLE'
                    # print(header)
                    d_config[header] = staff_list[num_list + 1]  # dictionary "header": "content"
                    num_list += 1
            # todo не берет послдний ==[ show bof
        return d_config

    def single_sign_for_entify(self, part_space, part_content):
        single_dict = {'description': '',
                       'shut': ''
                       }
        description = ''
        step_space = '    '  # step of level includiction

        # parse_sign_of_shutdown
        re_shut = re.compile('^((%s%s)shutdown$)' % (part_space, step_space), re.MULTILINE | re.DOTALL)
        founds_shut = re_shut.search(part_content)
        if founds_shut is not None:
            single_dict['shut'] = 'yes'

        # look_for_description_on_this_level_includiction
        re_descr = re.compile('^((%s%s)(description\s+(\"|)(?P<description>.*?)(\"|)$))' % (part_space, step_space),
                              re.MULTILINE | re.DOTALL)
        founds_descr = re_descr.search(part_content)
        if founds_descr is not None:
            description = founds_descr.group('description')
            single_dict['description'] = description

        return single_dict

    def parse_vprn(self, founds, vprn_name):
        # todo дописать в впрн поиск нат и внутри нат полиси
        vprn_content = {'name': '',
                        'content': '',
                        'description': '',
                        'shut': '',
                        'interfaces': {},
                        'subscriber_interfaces': {},
                        'static_route_entry': {}
                        }
        # print(num_vprn)
        vprn_content['content'] = founds.group('vprn_content')
        vprn_content['name'] = vprn_name

        # single_sign_for_entify_
        vprn_space = founds.group('space')
        vprn_single_dict_d = self.single_sign_for_entify(vprn_space, (vprn_content['content']))
        vprn_content['shut'] = vprn_single_dict_d['shut']
        vprn_content['description'] = vprn_single_dict_d['description']

        list_vprn_content = []
        re_vprn_spaceexit = re.compile('^(            .*?^            exit)', re.MULTILINE | re.DOTALL)
        list_vprn_content = (re_vprn_spaceexit.split(vprn_content['content']))

        for vprn_block in list_vprn_content:
            # PARSE_INTERFACES_FUNCTION
            single_interface = self.parse_interfaces(vprn_block)
            if single_interface != {}:
                if_name = single_interface['name']
                vprn_content['interfaces'][if_name] = single_interface

            # PARSE_SUBSCRIBER_INTERFACES_FUNCTION
            single_subscriber_if = self.parse_subscriber_interfaces(vprn_block)
            if single_subscriber_if != {}:
                subscriberif_name = single_subscriber_if['name']
                vprn_content['subscriber_interfaces'][subscriberif_name] = single_subscriber_if

                # PARSE_GROUP_INTERFACE_FUNCRION
                re_giface_spaceexit = re.compile('^(                .*?^                exit)',
                                                 re.MULTILINE | re.DOTALL)
                list_siface_content = (re_giface_spaceexit.split(single_subscriber_if['content']))

                for sifaces_block in list_siface_content:
                    single_group_interface = parse_group_interfaces(sifaces_block)
                    if single_group_interface != {}:
                        groupif_name = single_group_interface['name']
                        single_subscriber_if['group_interfaces'][groupif_name] = single_group_interface
            # todo написать сбор ospf
            # todo внутри которого поиск интерфейсав на которых mtu

            # PARSE STATIC_ROUTE_ENTRY
            single_static_re = self.parse_static_route_entry(vprn_block)
            if single_static_re != {}:
                static_re_name = single_static_re['name']
                vprn_content['static_route_entry'][static_re_name] = single_static_re
        return vprn_content

    def parse_group_interfaces(self, sifaces_block):
        single_group_interface = {}
        re_giface = re.compile(
            '^((?P<space>\s+)(group-interface\s+\"(?P<groupif_name>.*?)\"\s+.*?create)(?P<groupif_content>.*?)^(?P=space)exit)',
            re.MULTILINE | re.DOTALL)
        founds_gifaces = re_giface.search(sifaces_block)
        if founds_gifaces is not None:
            groupif_name = founds_gifaces.group('groupif_name')
            groupif_content = founds_gifaces.group('groupif_content')

            single_group_interface = {'name': groupif_name,
                                      'content': groupif_content,
                                      'saps': {},
                                      'description': '',
                                      'shut': '',
                                      'type': 'group-interface'
                                      }
            # new_part_dconfig['service']['vprns'][num_vprn]['subscriber_interfaces'][subscriberif_name]['group_interfaces'][groupif_name] = single_group_interface
            # single_sign_for_entify_
            gi_space = founds_gifaces.group('space')

            gi_single_dict = self.single_sign_for_entify(gi_space, groupif_content)
            single_group_interface['shut'] = gi_single_dict['shut']
            single_group_interface['description'] = gi_single_dict['description']

            # PARSE_LAG(SAP)_ON GROUP_INTERFACE
            list_groupif_content = []
            re_gi_spaceexit = re.compile('^(                    .*?^                    exit)',
                                         re.MULTILINE | re.DOTALL)
            list_groupif_content = (re_gi_spaceexit.split(single_group_interface['content']))

            for gi_block in list_groupif_content:
                single_sap = self.parse_saps(gi_block)
                if single_sap != {}:
                    lag_name = single_sap['lag_name']
                    single_group_interface['saps'][lag_name] = single_sap

        return single_group_interface


    def parse_ip_address(self, content_block):
        result_addr = {'addr_v4': {},
                       'addr_v6': {} }
        re_ifaddr_v4 = re.compile('^(?P<space>\s+)(?P<strv4_address>address '
                                  '(?P<ipv4_address>((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3})'
                                  '(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\S*))$)', re.MULTILINE | re.DOTALL)
        founds_ifaddr_v4 = re_ifaddr_v4.search(content_block)
        if founds_ifaddr_v4 is not None:
            strv4_address = founds_ifaddr_v4.group('strv4_address')
            ipv4_address = founds_ifaddr_v4.group('ipv4_address')
            single_ifaddr_v4 = {'type': 'ipv4',
                                'str_address': strv4_address,
                                'ipv4_address': ipv4_address
                                }
            result_addr['addr_v4'] = single_ifaddr_v4


        re_ifaddr_v6 = re.compile(
            "^((?P<space>\s+)(?P<strv6_address>address (?P<ipv6_address>\S+\:(|\S+)\:(|\S+)\:|\S+\:|\S+\:.*?))$)",
            re.MULTILINE)
        founds_ifaddr_v6 = re_ifaddr_v6.search(content_block)
        if founds_ifaddr_v6 is not None:
            ipv6_address = founds_ifaddr_v6.group('ipv6_address')
            strv6_address = founds_ifaddr_v6.group('strv6_address')
            # ipv6_part = founds_ifaddr_v6.group('ipv6_part')
            single_ifaddr_v6 = {'type': 'ipv6',
                                'str_address': strv6_address,
                                'ipv6_address': ipv6_address
                                }
            result_addr['addr_v6'] = single_ifaddr_v6

        return result_addr


    def parse_interfaces(self, vprn_block):
        # PARSE INTERFACES
        single_interface = {}
        re_iface = re.compile(
            '^((?P<space>\s+)(interface\s+\"(?P<if_name>.*?)\"\s+.*?create)(?P<if_content>.*?)^(?P=space)exit)',
            re.MULTILINE | re.DOTALL)
        founds_ifaces = re_iface.search(vprn_block)

        if founds_ifaces is not None:
            if_name = founds_ifaces.group('if_name')
            if_content = founds_ifaces.group('if_content')

            single_interface = {'name': if_name,
                                'content': if_content,
                                'description': '',
                                'shut': '',
                                'addr_v4': {},
                                'addr_v6': {},
                                #'type': '',
                                'dhcp_v4': None,
                                'dhcp_v6': None,
                                'type': 'group-interface'
                                }
            # new_part_dconfig['service']['vprns'][num_vprn]['interfaces'][if_name] = single_interface

            # single_sign_for_entify_
            if_space = founds_ifaces.group('space')
            if_single_dict = self.single_sign_for_entify(if_space, if_content)

            single_interface['shut'] = if_single_dict['shut']
            single_interface['description'] = if_single_dict['description']

            #   look_for_address(ipv4)_on_this_level_includition
            single_interface['addr_v4'] = self.parse_ip_address(if_content)['addr_v4']
            single_interface['addr_v6'] = self.parse_ip_address(if_content)['addr_v6']

            re_ifaceaddrsec = re.compile("(^\s*secondary\s+(?P<sec_ad>\S*)\s*$)", re.MULTILINE)
            single_interface['secondary'] = {}
            list_secondary = re_ifaceaddrsec.finditer(if_content)
            for sec in list_secondary:
                single_interface['secondary'][sec.group("sec_ad")] = ''

            re_ifaceloop = re.compile("^\s+(loopback)$", re.MULTILINE)
            loop = re_ifaceloop.search(if_content)
            if loop:
                single_interface['type'] = 'loopback'

            re_dhcp_server_v4 = re.compile("^                local-dhcp-server \"(.*?)\"\s*$", re.MULTILINE)
            re_dhcp_server_v6 = re.compile("^                    local-dhcp-server \"(.*?)\"\s*$", re.MULTILINE)
            # di_iface['dhcp_v4'] = None
            dhcp_v4 = re_dhcp_server_v4.search(if_content)
            if dhcp_v4 is not None:
                single_interface['dhcp_v4'] = dhcp_v4.group(1)

            # di_iface['dhcp_v6'] = None
            dhcp_v6 = re_dhcp_server_v6.search(if_content)
            if dhcp_v6 is not None:
                single_interface['dhcp_v6'] = dhcp_v6.group(1)

            # qos_in, qos_out
            re_qos_in_out = re.compile(
                '^((?P<space>\s+)ingress.*?qos\s+(?P<qos_in>\d+).*?egress.*?qos\s+(?P<qos_out>\d+).*?(?P=space)exit)',
                re.MULTILINE | re.DOTALL)
            founds_qos_param = re_qos_in_out.search(if_content)
            if founds_qos_param is not None:
                single_interface['qos_in'] = founds_qos_param.group('qos_in')
                single_interface['qos_out'] = founds_qos_param.group('qos_out')

            # sap
            re_sap = re.compile('sap\s+(?P<sap>(.*?))\s+create', re.MULTILINE | re.DOTALL)
            founds_sap_param = re_sap.search(if_content)
            if founds_sap_param is not None:
                single_interface['sap'] = founds_sap_param.group('sap')

            # new_part_dconfig['service']['vprns'][num_vprn]['interfaces'][if_name]['if_addr'] = single_ifaddr_v6
        return single_interface

    def parse_subscriber_interfaces(self, vprn_block):
        # MSA-6345
        # Added 'addresses_and_gw' to returning dict.
        re_flags = re.M | re.S
        re_addr_and_gws = re.compile(r'^ {16}address'
                                     r' (?P<addr_with_cidr>(?P<ip_ddn>\d+\.\d+\.\d+\.\d+)/(?P<cidr_mask>\d+))'
                                     r' gw-ip-address (?P<gw_ip_ddn>\d+\.\d+\.\d+\.\d+)', re_flags)
        # PARSE_SUBSCRIBER_INTERFACES
        single_subscriber_interface = {}
        re_siface = re.compile(
            '^((?P<space>\s+)(?P<subscriber_interface>subscriber-interface\s+\"(?P<subscriberif_name>.*?)\"\s+.*?create)(?P<subscriberif_content>.*?)^(?P=space)exit)',
            re.MULTILINE | re.DOTALL)
        founds_sifaces = re_siface.search(vprn_block)
        if founds_sifaces is not None:
            subscriberif_name = founds_sifaces.group('subscriberif_name')
            subscriberif_content = founds_sifaces.group('subscriberif_content')

            subscr_iface_addr_and_gws = {}
            subscr_if_addresses = re_addr_and_gws.finditer(subscriberif_content)
            if subscr_if_addresses:
                for addr_and_gw in subscr_if_addresses:
                    addr = addr_and_gw.group('addr_with_cidr')
                    ip_ddn = addr_and_gw.group('ip_ddn')
                    cidr_mask = addr_and_gw.group('cidr_mask')
                    gw_ip_ddn = addr_and_gw.group('gw_ip_ddn')
                    subscr_iface_addr_and_gws[addr] = {
                        'ip_ddn': ip_ddn,
                        'cidr_mask': cidr_mask,
                        'gw_ip_ddn': gw_ip_ddn
                    }

            single_subscriber_interface = {'name': subscriberif_name,
                                           'content': subscriberif_content,
                                           'description': '',
                                           'group_interfaces': {},
                                           'shut': '',
                                           'addr_v4': {},
                                           'addr_v6': {},
                                           'type': 'subinterface',
                                           'addresses_and_gw': subscr_iface_addr_and_gws
                                           }

            #   look_for_address(ipv4)_on_this_level_includition
            single_subscriber_interface['addr_v4'] = (self.parse_ip_address(subscriberif_content))['addr_v4']
            single_subscriber_interface['addr_v6'] = (self.parse_ip_address(subscriberif_content))['addr_v6']

            # new_part_dconfig['service']['vprns'][num_vprn]['subscriber_interfaces'][subscriberif_name] = single_subscriber_interface
            # single_sign_for_entify_
            si_space = founds_sifaces.group('space')
            si_single_dict = self.single_sign_for_entify(si_space, subscriberif_content)
            single_subscriber_interface['shut'] = si_single_dict['shut']
            single_subscriber_interface['description'] = si_single_dict['description']
        return single_subscriber_interface

    # dlocal_d_config['current']['echo "Service Configuration"']['service']['vprns']['100']['setap_content']['static_route_entry']['5.166.92.0/22']['preference']
    def parse_static_route_entry(self, vprn_block):
        # PARSE STATIC_ROUTE_ENTRY
        single_static_re = {}
        re_static_re = re.compile(
            '^((?P<space>\s+)(?P<static_re_str>static-route-entry\s+(?P<static_re_name>.*?)\s+.*?)(?P<static_re_content>.*?)^(?P=space)exit)',
            re.MULTILINE | re.DOTALL)
        founds_static_re = re_static_re.search(vprn_block)
        if founds_static_re is not None:
            single_static_re = {'name': founds_static_re.group('static_re_name'),
                                'addr': founds_static_re.group('static_re_name'),
                                'content': founds_static_re.group('static_re_content'),
                                'static_re_str': founds_static_re.group('static_re_str'),
                                'next-hop': '',
                                'preference': '',
                                'metric': '',
                                'description': '',
                                'shut': '',
                                'type': 'static-route-entry'
                                }
            try:
                single_static_re['preference'] = (
                    re.search('(preference (?P<num>\d+))', (single_static_re['content'])).group('num'))
            except:
                pass
            try:
                single_static_re['next-hop'] = (re.search('(?P<next_hop>next-hop|indirect|blackhole|black-hole)',
                                                          (single_static_re['content'])).group('next_hop'))
            except:
                pass
            try:
                single_static_re['metric'] = (
                    re.search('(metric (?P<num>\d+))', (single_static_re['content'])).group('num'))
            except:
                pass

            # single_sign_for_entify_
            si_space = founds_static_re.group('space')
            sre_single_dict = self.single_sign_for_entify(si_space, (single_static_re['content']))
            single_static_re['shut'] = sre_single_dict['shut']
            single_static_re['description'] = sre_single_dict['description']

        return single_static_re

    def parse_saps(self, vpls_block):
        single_sap = {}
        re_saps = re.compile(
            '^((?P<space>\s+)(?P<sap_name>sap\s+(?P<lag_name>lag.*?)\s+.*?create)(?P<sap_content>.*?)^(?P=space)exit)',
            re.MULTILINE | re.DOTALL)
        founds_saps = re_saps.search(vpls_block)
        if founds_saps is not None:
            lag_name = founds_saps.group('lag_name')
            sap_content = founds_saps.group('sap_content')
            sap_name = founds_saps.group('sap_name')
            single_sap = {'lag_name': lag_name,
                          'name': sap_name, #sap_name
                          'lag': {'num': '',
                                  'ev': '',
                                  'iv': ''},
                          'content': sap_content,
                          'description': '',
                          'shut': '',
                          'type': 'saps'
                          }
            # single_sign_for_entify_
            sap_space = founds_saps.group('space')
            sap_single_dict = self.single_sign_for_entify(sap_space, sap_content)
            single_sap['shut'] = sap_single_dict['shut']
            single_sap['description'] = sap_single_dict['description']

            re_partlag = re.compile('(lag-(?P<nl>\S+):(?P<ev>\S+)\.(?P<iv>\S+))', re.MULTILINE | re.DOTALL)
            founds_nl = re_partlag.search(lag_name)
            if founds_nl is not None:
                single_sap['lag']['num'] = founds_nl.group('nl')
                single_sap['lag']['ev'] = founds_nl.group('ev')
                single_sap['lag']['iv'] = founds_nl.group('iv')

        return single_sap

    def parse_vpls(self, founds, vpls_name):
        vpls_content = founds.group('vpls_content')
        single_vpls = {}
        single_vpls = {'name': vpls_name,
                       'description': '',
                       'content': vpls_content,
                       'saps': {},
                       'shut': ''
                       }
        # new_part_dconfig['service']['vplss'][num_vpls] = single_vpls

        # single_sign_for_entify_
        vpls_space = founds.group('space')
        vpls_single_dict = self.single_sign_for_entify(vpls_space, vpls_content)
        single_vpls['shut'] = vpls_single_dict['shut']
        single_vpls['description'] = vpls_single_dict['description']

        # PARSE_SAPS
        list_vpls_content = []
        re_vpls_spaceexit = re.compile('^(            .*?^            exit)', re.MULTILINE | re.DOTALL)
        list_vpls_content = (re_vpls_spaceexit.split(single_vpls['content']))

        for vpls_block in list_vpls_content:
            single_sap = self.parse_saps(vpls_block)
            if single_sap != {}:
                lag_name = single_sap['lag_name']
                single_vpls['saps'][lag_name] = single_sap

                # single_vpls['saps'][lag_name] = single_sap
            # print(vpls_block)

        return single_vpls

    def parse_nat(self, founds):
        nat_policies = {}
        nats_full_sc = founds.group(1)
        re_nat_spaceexit = re.compile('^(            .*?^            exit)', re.MULTILINE | re.DOTALL)
        list_nat_sc = re_nat_spaceexit.split(nats_full_sc)

        nat_policies['nat_policy'] = {}
        re_nat_policy = re.compile(
            '^((?P<space>\s+)nat-policy\s+\"(?P<natpol_name>.*?)\"(?P<natpol_content>.*?)^(?P=space)exit)',
            re.MULTILINE | re.DOTALL)
        for nat_policy in list_nat_sc:
            founds_nat = re_nat_policy.search(nat_policy)
            if founds_nat is not None:
                natpol_name = founds_nat.group('natpol_name')
                natpol_content = founds_nat.group('natpol_content')
                single_nat = {}
                single_natpol = {'name': natpol_name,
                                 'content': natpol_content,
                                 'description': '',
                                 'shut': '',
                                 'type': 'nat-policy'
                                 }
                nat_policies['nat_policy'][natpol_name] = single_natpol

                # single_sign_for_entify_
                natpol_space = founds_nat.group('space')
                step_space = '    '  # step of level includiction

                #   parse_sign_of_shutdown
                re_shut = re.compile('^((%s%s)shutdown$)' % (natpol_space, step_space), re.MULTILINE | re.DOTALL)
                founds_shut = re_shut.search(natpol_content)
                if founds_shut is not None:
                    nat_policies['nat_policy'][natpol_name]['shut'] = 'yes'

                # look_for_description_on_this_level_includiction
                re_natpol_descr = re.compile(
                    '^((%s%s)(description\s+(?P<natpol_description>.*?$)))' % (natpol_space, step_space),
                    re.MULTILINE | re.DOTALL)
                founds_descr = re_natpol_descr.search(natpol_content)
                if founds_descr is not None:
                    natpol_description = founds_descr.group('natpol_description')

                    nat_policies['nat_policy'][natpol_name]['natpol_description'] = natpol_description
        return nat_policies

    def parse_oper_group(self, founds, og_name):
        single_oper_group = {}
        og_content = founds.group('og_content')
        single_oper_group = {'name': og_name,
                             'content': og_content,
                             'type': 'oper-group'
                             }
        return single_oper_group

    def parse_qossap(self, founds, num):
        single_qossap = {}
        single_qossap = {'name': founds.group('name'),
                         'num': num,
                         'description': '',
                         'shut': '',
                         'content': founds.group('content'),
                         'ip_criteria': {},
                         'ipv6_criteria': {},
                         'queues': {},
                         'fcs': {},
                         'policer': {},
                         'type': 'qos'
                         }
        # single_sign_for_entify_
        qsap_space = founds.group('space')
        qos_single_dict = self.single_sign_for_entify(qsap_space, single_qossap['content'])
        single_qossap['shut'] = qos_single_dict['shut']
        single_qossap['description'] = qos_single_dict['description']

        list_qossap = []
        re_space_exit = re.compile('^(            .*?^            exit)', re.MULTILINE | re.DOTALL)
        list_qossap = (re_space_exit.split(single_qossap['content']))
        for element_qossap in list_qossap:
            # Parse equeue
            re_queue = re.compile(
                '^((?P<space>\s+)(?P<name_q>queue\s+(?P<num_q>\d+).*?create)(?P<content_q>.*?)^(?P=space)exit)',
                re.MULTILINE | re.DOTALL)
            founds_queue = re_queue.search(element_qossap)
            if founds_queue is not None:
                num_q = founds_queue.group('num_q')
                single_queue = {'name_q': founds_queue.group('name_q'),
                                'num_q': num_q,
                                'content': founds_queue.group('content_q')}
                single_qossap['queues'][num_q] = single_queue
            # parse ip-criteria
            re_ipcrit = re.compile('^((?P<space>\s+)(?P<name_ipc>ip-criteria)(?P<content_ipc>.*?)^(?P=space)exit)',
                                   re.MULTILINE | re.DOTALL)
            founds_ipcrit = re_ipcrit.search(element_qossap)
            if founds_ipcrit is not None:
                name_ipc = founds_ipcrit.group('name_ipc')
                single_ipcrit = {'type': name_ipc,
                                 'content': founds_ipcrit.group('content_ipc'),
                                 'entries': {}
                                 }
                re_space_exit = re.compile('^(                .*?^                exit)', re.MULTILINE | re.DOTALL)
                list_ipcrit = (re_space_exit.split(single_ipcrit['content']))
                for el_list_ipcrit in list_ipcrit:
                    re_entry = re.compile(
                        '^((?P<space>\s+)(?P<name_e>entry\s+(?P<e_num>\d+)\s+create)(?P<content_e>.*?)^(?P=space)exit)',
                        re.MULTILINE | re.DOTALL)
                    founds_entry = re_entry.search(el_list_ipcrit)
                    if founds_entry is not None:
                        e_num = founds_entry.group('e_num')
                        single_entry = {'name': founds_entry.group('name_e'),
                                        'num': e_num,
                                        'content': founds_entry.group('content_e')}
                        single_ipcrit['entries'][e_num] = single_entry

                single_qossap['ip_criteria'] = single_ipcrit

            # parse ipv6-criteria
            re_ipcrit = re.compile('^((?P<space>\s+)(?P<name_ipc>ipv6-criteria)(?P<content_ipc>.*?)^(?P=space)exit)',
                                   re.MULTILINE | re.DOTALL)
            founds_ipcrit = re_ipcrit.search(element_qossap)
            if founds_ipcrit is not None:
                name_ipc = founds_ipcrit.group('name_ipc')
                single_ipcrit = {'type': name_ipc,
                                 'content': founds_ipcrit.group('content_ipc'),
                                 'entries': {}
                                 }
                re_space_exit = re.compile('^(                .*?^                exit)', re.MULTILINE | re.DOTALL)
                list_ipcrit = (re_space_exit.split(single_ipcrit['content']))
                for el_list_ipcrit in list_ipcrit:
                    re_entry = re.compile(
                        '^((?P<space>\s+)(?P<name_e>entry\s+(?P<e_num>\d+)\s+create)(?P<content_e>.*?)^(?P=space)exit)',
                        re.MULTILINE | re.DOTALL)
                    founds_entry = re_entry.search(el_list_ipcrit)
                    if founds_entry is not None:
                        e_num = founds_entry.group('e_num')
                        single_entry = {'name': founds_entry.group('name_e'),
                                        'num': e_num,
                                        'content': founds_entry.group('content_e')}
                        single_ipcrit['entries'][e_num] = single_entry

                single_qossap['ipv6_criteria'] = single_ipcrit

            # parse fc
            re_fc = re.compile(
                '^((?P<space>\s+)(?P<declare>fc\s+(?P<name>.*?)\s+create)(?P<content_fc>.*?)^(?P=space)exit)',
                re.MULTILINE | re.DOTALL)
            founds_fc = re_fc.search(element_qossap)
            if founds_fc is not None:
                name_fc = founds_fc.group('name')
                single_fc = {'declare': founds_fc.group('declare'),
                             'name': name_fc,
                             'content': founds_fc.group('content_fc')}
                single_qossap['fcs'][name_fc] = single_fc

            # parse_policer
            re_policer = re.compile(
                '^((?P<space>\s+)(?P<declare>policer\s+(?P<name_p>.*?)\s+create)(?P<content_p>.*?)^(?P=space)exit)',
                re.MULTILINE | re.DOTALL)
            founds_policer = re_policer.search(element_qossap)
            if founds_policer is not None:
                name_p = founds_policer.group('name_p')
                single_p = {'declare': founds_policer.group('declare'),
                            'name': name_p,
                            'content': founds_policer.group('content_p')}
                single_qossap['policer'][name_p] = single_p
        return single_qossap

    def parse_local_server(self, founds, lserver_name, l_space):
        # MSA-6345
        # Added ipv6 flag to DHCP server and subnets with their options
        # to every pool in ipv4 servers.
        re_flags = re.M | re.S

        re_subnet =  re.compile(r'^ {24}subnet (?P<subnet_with_mask>(?P<subnet>\d+\.\d+\.\d+\.\d+)/(?P<cidr_mask>\d+))'
                                r' create'
                                r'(?P<subnet_cont>.*?)'
                                r'^ {24}exit', re_flags)
        re_subnet_options =  re.compile(r'^ {28}options\s*?'
                                        r'subnet-mask (?P<mask_option>\d+\.\d+\.\d+\.\d+)\s*?'
                                        r'default-router (?P<router_option>\d+\.\d+\.\d+\.\d+)\s*?'
                                        r'^ {28}exit', re_flags)

        single_lserver = {}
        single_lserver = {'name': lserver_name,
                          'content': founds,
                          'description': '',
                          'shut': '',
                          'pools': {},
                          'type': 'local-server',
                          'ipv6': False
                          }
        # single_sign_for_entify_
        # lserv_space = founds_lserver.group('space')
        support_dict = self.single_sign_for_entify(l_space, single_lserver['content'])
        single_lserver['shut'] = support_dict['shut']
        single_lserver['description'] = support_dict['description']
        if 'dhcpv6-server' in single_lserver['description'] or 'DHCP-V6' in lserver_name:
            single_lserver['ipv6'] = True

        list_pools = []
        re_pool = re.compile('^((?P<space>\s+)(pool\s+(?P<name_p>\S+)\s+.*?create)(?P<content>.*?)^(?P=space)exit)',
                             re.MULTILINE | re.DOTALL)
        list_pools = re_pool.finditer(single_lserver['content'])
        dict_pools = {}
        if list_pools != []:
            for founds_pools in list_pools:
                name_p = founds_pools.group('name_p')
                single_pool = {'name': name_p,
                               'content': founds_pools.group('content'),
                               'description': '',
                               'shut': '',
                               'type': 'pool',
                               'subnets': {}
                               }

                if not single_lserver['ipv6']:
                    pool_subnets = re_subnet.finditer(single_pool['content'])
                    if pool_subnets:
                        for subnet in pool_subnets:
                            raw_subnet_content = subnet.group('subnet_cont')
                            subnet_key = subnet.group('subnet_with_mask')
                            single_pool['subnets'][subnet_key] = {
                                'subnet_ddn': subnet.group('subnet'),
                                'subnet_mask_cidr': subnet.group('cidr_mask'),
                                'raw_content': raw_subnet_content,
                                'options':{}
                            }
                            options = re_subnet_options.search(raw_subnet_content)
                            if options:
                                single_pool['subnets'][subnet_key]['options'] = {
                                    'subnet_mask': options.group('mask_option'),
                                    'default-router': options.group('router_option')
                                }
                # single_sign_for_entify_
                p_space = founds_pools.group('space')
                support_dict = self.single_sign_for_entify(p_space, single_pool['content'])
                single_pool['shut'] = support_dict['shut']
                single_pool['description'] = support_dict['description']

                dict_pools[name_p] = single_pool

        single_lserver['pools'] = dict_pools
        # single_vprn['local_dhcp_servers'][name_lserver] = single_lserver

        return single_lserver

    def echo_filter_match_lists_conf_to_dict(self, part_dconfig, header):
        new_part_dconfig = {'FULL': {}, 'filter_match_list': {}}
        new_part_dconfig['FULL'] = part_dconfig

        re_filter_ml = re.compile('^((?P<space>\s+)match-list(.*?)^(?P=space)exit)', re.MULTILINE | re.DOTALL)
        founds = re_filter_ml.search(part_dconfig)
        new_part_dconfig['filter_match_list'] = {}
        if founds is not None:
            founds_content = founds.group(3)  # level include 4 space
        else:
            new_part_dconfig['filter_match_list'] = {}
            return new_part_dconfig
        # if 'double' not in header.lower():
        #     return new_part_dconfig

        list_filterml = []
        re_space_exit = re.compile('^(            .*?^            exit)', re.MULTILINE | re.DOTALL)
        list_filterml = (re_space_exit.split(founds_content))
        dict_filterml = {}
        for elenent_listfilter in list_filterml:
            re_ip_prefix = re.compile(
                '^((?P<space>\s+)(?P<str_prefix>ip-prefix-list\s+(?P<name_prefix>\S+).*?create)(?P<content>.*?)^(?P=space)exit)',
                re.MULTILINE | re.DOTALL)
            founds_ip_prefix = re_ip_prefix.search(elenent_listfilter)
            if founds_ip_prefix is not None:
                name_prefix = founds_ip_prefix.group('name_prefix')
                single_ip_prefix = {'name': name_prefix,
                                    'str_prefix': founds_ip_prefix.group('name_prefix'),
                                    'content': founds_ip_prefix.group('content'),
                                    'description': '',
                                    'prefixes': {},
                                    'type': 'prefix'
                                    }
                re_prefix = re.compile('(prefix\s+(?P<addr_prefix>.*?)$)', re.MULTILINE | re.DOTALL)
                list_pre = re_prefix.finditer(single_ip_prefix['content'])
                for pre in list_pre:
                    # print(pre.group('addr_prefix'))
                    single_ip_prefix['prefixes'][pre.group('addr_prefix')] = ''

                new_part_dconfig['filter_match_list'][name_prefix] = single_ip_prefix

        return new_part_dconfig

    # d_config['current']['echo "Port Configuration"']
    def echo_port_conf_to_dict_N(self, part_dconfig, header):
        new_part_dconfig = {}
        new_part_dconfig['FULL'] = part_dconfig
        new_part_dconfig['ports'] = {}
        re_ports = re.compile('^((?P<space>\s+)port\s+\d+\/\d+\/\d+.*?^(?P=space)exit)', re.MULTILINE | re.DOTALL)
        staff_list = (re_ports.split(part_dconfig))

        for blok_s in staff_list:
            re_ports = re.compile(
                '^((?P<space>\s+)(?P<port_name>port\s+\d+\/\d+\/\d+)(?P<port_content>.*?^(?P=space)exit))',
                re.MULTILINE | re.DOTALL)
            founds = (re_ports.search(blok_s))
            if founds is not None:
                port_name = (re_ports.search(blok_s)).group('port_name')
                port_content = (re_ports.search(blok_s)).group('port_content')
                new_part_dconfig['ports'][port_name] = {'name': port_name,
                                                        'content': port_content,
                                                        'description': '',
                                                        'shut': '',
                                                        'qinq_type': '',
                                                        'mode': '',
                                                        'type': 'port'
                                                        }

                # single_sign_for_entify_
                p_space = (re_ports.search(blok_s)).group('space')

                port_single_dict = self.single_sign_for_entify(p_space, port_content)
                new_part_dconfig['ports'][port_name]['shut'] = port_single_dict['shut']
                new_part_dconfig['ports'][port_name]['description'] = port_single_dict['description']

                re_port_qinq = re.compile("^\s+encap-type (dot1q|qinq)$", re.MULTILINE)
                qinq = re_port_qinq.search(port_content)
                if None != qinq and 'qinq' == qinq.group(1):
                    new_part_dconfig['ports'][port_name]['qinq_type'] = 'customer'
                else:
                    new_part_dconfig['ports'][port_name]['qinq_type'] = 'normal'

                re_port_mode = re.compile("^\s+mode (hybrid|access)$", re.MULTILINE)
                port_mode = re_port_mode.search(port_content)
                if None != port_mode:
                    new_part_dconfig['ports'][port_name]['mode'] = port_mode.group(1)
                else:
                    new_part_dconfig['ports'][port_name]['mode'] = ''

                re_port_mode = re.compile("^\s+mode (hybrid|access)$", re.MULTILINE)
                port_mode = re_port_mode.search(port_content)
                if None != port_mode:
                    new_part_dconfig['ports'][port_name]['mode'] = port_mode.group(1)
                else:
                    new_part_dconfig['ports'][port_name]['mode'] = ''

        return new_part_dconfig

    # d_config[bras]['echo "LAG Configuration"']
    def echo_lag_conf_to_dict_N(self, part_dconfig, header):
        new_part_dconfig = {}
        new_part_dconfig['FULL'] = part_dconfig

        new_part_dconfig['lags'] = {}
        re_lags = re.compile('^((?P<space>\s+)lag\s+\d+.*?^(?P=space)exit)', re.MULTILINE | re.DOTALL)
        staff_list = (re_lags.split(part_dconfig))
        for blok_s in staff_list:
            re_lags = re.compile('^((?P<space>\s+)(?P<lag_name>lag\s+\d+)(?P<lag_content>.*?^(?P=space)exit))',
                                 re.MULTILINE | re.DOTALL)
            founds = (re_lags.search(blok_s))
            if founds is not None:
                lag_name = (re_lags.search(blok_s)).group('lag_name')
                lag_content = (re_lags.search(blok_s)).group('lag_content')
                new_part_dconfig['lags'][lag_name] = {'name': lag_name,
                                                      'content': lag_content,
                                                      'description': '',
                                                      'shut': '',
                                                      'qinq_type': '',
                                                      'res_optimization': '',
                                                      'mode': '',
                                                      'type': 'lag',
                                                      'members': []
                                                      }

                # single_sign_for_entify_
                lag_space = (re_lags.search(blok_s)).group('space')
                lag_single_dict = self.single_sign_for_entify(lag_space, lag_content)

                new_part_dconfig['lags'][lag_name]['shut'] = lag_single_dict['shut']
                new_part_dconfig['lags'][lag_name]['description'] = lag_single_dict['description']

                re_lag_qinq = re.compile("^\s+encap-type (dot1q|qinq)$", re.MULTILINE)
                qinq = re_lag_qinq.search(lag_content)
                if None != qinq and 'qinq' == qinq.group(1):
                    new_part_dconfig['lags'][lag_name]['qinq_type'] = 'customer'
                else:
                    new_part_dconfig['lags'][lag_name]['qinq_type'] = 'normal'

                re_res_optim = re.compile(
                    "^\s+access\n            adapt-qos distribute include-egr-hash-cfg\n            "
                    "per-fp-ing-queuing\n            per-fp-egr-queuing\n            "
                    "per-fp-sap-instance\n        exit$", re.DOTALL | re.MULTILINE)
                res_optimization = re_res_optim.search(lag_content)
                if None != res_optimization:
                    new_part_dconfig['lags'][lag_name]['res_optimization'] = 1
                else:
                    new_part_dconfig['lags'][lag_name]['res_optimization'] = 0

                re_lag_mode = re.compile("^\s+mode (hybrid|access)$", re.MULTILINE)
                lag_mode = re_lag_mode.search(lag_content)
                if None != lag_mode:
                    new_part_dconfig['lags'][lag_name]['mode'] = lag_mode.group(1)
                else:
                    new_part_dconfig['lags'][lag_name]['mode'] = ''


                re_ports = re.compile("^\s+port\s+(?P<port>.*?)(\s+|)$", re.DOTALL | re.MULTILINE)
                members_ports = re_ports.finditer(lag_content)
                if None != members_ports:
                    for port in members_ports:
                        (new_part_dconfig['lags'][lag_name]['members']).append(port.group('port'))

                # todo реализовать аналог того что в старом parse_ifaces собираается



        return new_part_dconfig

    # d_config[bras]['echo "Service Configuration"']
    def echo_service_conf_to_dict_N(self, part_dconfig, header):
        # service -> vprn | vpls | sdp | customer | oper-group | pw-template | ipfix | nat
        new_part_dconfig = {}
        new_part_dconfig['FULL'] = part_dconfig
        re_service = re.compile('^((?P<space>\s+)service(.*?)^(?P=space)exit)', re.MULTILINE | re.DOTALL)
        founds = re_service.search(part_dconfig)
        new_part_dconfig['service'] = {}
        if founds is not None:
            new_part_dconfig['service']['full'] = founds.group(3)  # level include 4 space
        else:
            new_part_dconfig['service']['full'] = ''

        list_sc = []
        re_space_exit = re.compile('^(        .*?^        exit)', re.MULTILINE | re.DOTALL)
        list_sc = (re_space_exit.split(new_part_dconfig['service']['full']))

        # parse_vprn
        new_part_dconfig['service']['vprns'] = {}
        re_vprn = re.compile(
            '^((?P<space>\s+)(?P<vprn_name>vprn\s+(?P<num_vprn>\d+).*?create$)(?P<vprn_content>.*?)^(?P=space)exit)',
            re.MULTILINE | re.DOTALL)
        for part_sc in list_sc:
            founds = re_vprn.search(part_sc)
            if founds is not None:
                # single_vprn = {'vprn_name': '',
                #                'declare_content': {},
                #                'setap_content': {}
                #               }
                num_vprn = founds.group('num_vprn')
                vprn_name = founds.group('vprn_name')
                if num_vprn not in (new_part_dconfig['service']['vprns']):
                    # todo дописать в впрн поиск нат и внутри нат полиси
                    vprn_content_d = self.parse_vprn(founds, vprn_name)
                    new_part_dconfig['service']['vprns'][num_vprn] = {}
                    new_part_dconfig['service']['vprns'][num_vprn]['name'] = vprn_name
                    new_part_dconfig['service']['vprns'][num_vprn]['declare_content'] = vprn_content_d
                elif num_vprn in (new_part_dconfig['service']['vprns']):
                    vprn_content_s = self.parse_vprn(founds, vprn_name)
                    new_part_dconfig['service']['vprns'][num_vprn]['setap_content'] = vprn_content_s

        # print(new_part_dconfig['service'].keys())

        # parse_vpls
        new_part_dconfig['service']['vplss'] = {}
        re_vpls = re.compile(
            '^((?P<space>\s+)(?P<vpls_name>vpls\s+(?P<num_vpls>\d+).*?create$)(?P<vpls_content>.*?)^(?P=space)exit)',
            re.MULTILINE | re.DOTALL)
        for part_sc in list_sc:
            founds = re_vpls.search(part_sc)
            if founds is not None:
                num_vpls = founds.group('num_vpls')
                vpls_name = founds.group('vpls_name')
                if num_vpls not in (new_part_dconfig['service']['vplss']):
                    vpls_content_d = self.parse_vpls(founds, vpls_name)
                    new_part_dconfig['service']['vplss'][num_vpls] = {}
                    new_part_dconfig['service']['vplss'][num_vpls]['name'] = vpls_name
                    new_part_dconfig['service']['vplss'][num_vpls]['declare_content'] = vpls_content_d
                elif num_vpls in (new_part_dconfig['service']['vplss']):
                    vpls_content_s = self.parse_vpls(founds, vpls_name)
                    new_part_dconfig['service']['vplss'][num_vpls]['setap_content'] = vpls_content_s

        # print(new_part_dconfig['service'].keys())

        # parse_nats
        new_part_dconfig['service']['nats'] = {}
        re_nats = re.compile('^((?P<space>        )nat.*?^(?P=space)exit)', re.MULTILINE | re.DOTALL)
        for part_sc in list_sc:
            founds = re_nats.search(part_sc)
            if founds is not None:
                if new_part_dconfig['service']['nats'] == {}:
                    nat_content_d = self.parse_nat(founds)
                    new_part_dconfig['service']['nats']['declare_content'] = nat_content_d
                elif new_part_dconfig['service']['nats'] != {}:
                    nat_content_s = self.parse_nat(founds)
                    new_part_dconfig['service']['nats']['setap_content'] = nat_content_s
        # print(new_part_dconfig['service'].keys())

        # #parse_oper_groups
        new_part_dconfig['service']['oper_groups'] = {}
        re_oper_group = re.compile(
            '^((?P<space>\s+)oper-group\s+\"(?P<og_name>.*?)\"\s+create(?P<og_content>.*?)^(?P=space)exit)',
            re.MULTILINE | re.DOTALL)
        for part_sc in list_sc:
            founds = re_oper_group.search(part_sc)
            if founds is not None:
                og_name = founds.group('og_name')
                if og_name not in (new_part_dconfig['service']['oper_groups']):
                    new_part_dconfig['service']['oper_groups'][og_name] = {}
                    og_content_d = self.parse_oper_group(founds, og_name)
                    new_part_dconfig['service']['oper_groups'][og_name]['declare_content'] = og_content_d
                elif og_name in (new_part_dconfig['service']['oper_groups']):
                    og_content_s = self.parse_oper_group(founds, og_name)
                    new_part_dconfig['service']['oper_groups'][og_name]['setap_content'] = og_content_s
        # print(new_part_dconfig['service'].keys())

        # parse_ipfix
        new_part_dconfig['service']['ipfix'] = {}
        re_ipfix_bloks = re.compile('^((?P<space>\s+)ipfix(?P<ipfix_bloks>.*?)^(?P=space)exit)',
                                    re.MULTILINE | re.DOTALL)
        for part_sc in list_sc:
            founds = re_ipfix_bloks.search(part_sc)
            if founds is not None:
                new_part_dconfig['service']['ipfix']['full_ipfix'] = founds.group('ipfix_bloks')
                # todo: if will be needed - to do parse this block

        # parse_pw_templates
        new_part_dconfig['service']['pw_templates'] = {}
        re_pwtemplate = re.compile(
            '^((?P<space>\s+)pw-template\s+(?P<pwt_num>\d+)\s+create(?P<pwt_content>.*?)^(?P=space)exit)',
            re.MULTILINE | re.DOTALL)
        for part_sc in list_sc:
            founds = re_pwtemplate.search(part_sc)
            if founds is not None:
                pwt_num = founds.group('pwt_num')
                pwt_content = founds.group('pwt_content')
                new_part_dconfig['service']['pw_templates'][pwt_num] = pwt_content
                # todo: if will be needed - to do parse this block

        # parse_sdp
        new_part_dconfig['service']['sdps'] = {}
        re_sdp = re.compile('^((?P<space>\s+)(?P<sdp_name>sdp\s+(?P<sdp_num>\d+)\s+.*?create)(?P<sdp_content>.*)exit)',
                            re.MULTILINE | re.DOTALL)
        for part_sc in list_sc:
            founds = re_sdp.search(part_sc)
            if founds is not None:
                sdp_num = founds.group('sdp_num')
                sdp_name = founds.group('sdp_name')
                sdp_content = founds.group('sdp_content')
                single_sdp = {}
                single_sdp = {'name': sdp_name,
                              'sdp_num': sdp_num,
                              'content': sdp_content
                              }
                new_part_dconfig['service']['sdps'][sdp_num] = single_sdp

        # parse_customers
        new_part_dconfig['service']['customers'] = {}
        re_customer = re.compile(
            '^((?P<space>\s+)(?P<customer_name>customer\s+(?P<customer_num>.*?)\s+.*?create)(?P<customer_content>.*?)exit)',
            re.MULTILINE | re.DOTALL)
        for part_sc in list_sc:
            founds = re_customer.search(part_sc)
            if founds is not None:
                customer_num = founds.group('customer_num')
                customer_name = founds.group('customer_name')
                customer_content = founds.group('customer_content')
                single_customer = {}
                single_customer = {'name': customer_name,
                                   'customer_num': customer_num,
                                   'content': customer_content
                                   }
                new_part_dconfig['service']['customers'][customer_num] = single_customer

        return new_part_dconfig

    def echo_router_network_side_conf_to_dict(self, part_dconfig, header):
        new_part_dconfig = {'FULL': part_dconfig, 'router_base':{}}
        new_part_dconfig['FULL'] = part_dconfig
        if part_dconfig is None or part_dconfig == '':
            return new_part_dconfig

        list_interfaces = []
        re_inter_spaceexit = re.compile('^(        .*?^        exit)', re.MULTILINE | re.DOTALL)
        list_router_base_content = (re_inter_spaceexit.split(part_dconfig))


        for interface in list_router_base_content:
            #PARSE_INTERFACES_FUNCTION
            single_interface = self.parse_interfaces(interface)
            if single_interface != {} :
                if_name = single_interface['if_name']
                new_part_dconfig['router_base'][if_name] = single_interface


        return new_part_dconfig

    # d_config[bras]['echo "QoS Policy Configuration"'] or d_config[bras]['echo "QoS Policy Configuration" DOUBLE']
    def echo_qos_policy_conf_to_dict(self, part_dconfig, header):
        new_part_dconfig = {'FULL': {}, 'qos': {}}
        new_part_dconfig['FULL'] = part_dconfig

        re_qos = re.compile('^((?P<space>\s+)qos(.*?)^(?P=space)exit)', re.MULTILINE | re.DOTALL)
        founds = re_qos.search(part_dconfig)
        new_part_dconfig['qos'] = {}
        if founds is not None:
            new_part_dconfig['qos']['full'] = founds.group(3)  # level include 4 space
        else:
            new_part_dconfig['qos']['full'] = ''
        if 'double' not in header.lower():
            return new_part_dconfig
        list_qos = []
        re_space_exit = re.compile('^(        .*?^        exit)', re.MULTILINE | re.DOTALL)
        list_qos = (re_space_exit.split(new_part_dconfig['qos']['full']))
        dict_qos = {}
        for elenent_listqos in list_qos:
            re_ingress = re.compile(
                '^((?P<space>\s+)(?P<name>sap-ingress\s+(?P<num_in>\d+).*?create)(?P<content>.*?)^(?P=space)exit)',
                re.MULTILINE | re.DOTALL)
            founds_in = re_ingress.search(elenent_listqos)
            if founds_in is not None:
                num_in = founds_in.group('num_in')
                single_in = self.parse_qossap(founds_in, num_in)
                if num_in not in dict_qos:
                    dict_qos[num_in] = {'ingress': single_in}
                else:
                    dict_qos[num_in]['ingress'] = single_in

            re_egress = re.compile(
                '^((?P<space>\s+)(?P<name>sap-egress\s+(?P<num_eg>\d+).*?create)(?P<content>.*?)^(?P=space)exit)',
                re.MULTILINE | re.DOTALL)
            founds_eg = re_egress.search(elenent_listqos)
            if founds_eg is not None:
                num_eg = founds_eg.group('num_eg')
                single_eg = self.parse_qossap(founds_eg, num_eg)
                if num_eg not in dict_qos:
                    dict_qos[num_eg] = {'egress': single_eg}
                else:
                    dict_qos[num_eg]['egress'] = single_eg

            # todo проверить что собирается индентично старому



        new_part_dconfig['qos']['saps'] = dict_qos
        return new_part_dconfig

    def echo_local_DHCP_Server_services_conf_to_dict(self, part_dconfig, header):
        new_part_dconfig = {'FULL': {}, 'service': {}}
        new_part_dconfig['FULL'] = part_dconfig

        re_service = re.compile('^((?P<space>\s+)service(.*?)^(?P=space)exit)', re.MULTILINE | re.DOTALL)
        founds = re_service.search(part_dconfig)
        new_part_dconfig['service'] = {}
        service_content = ''
        if founds is None:
            new_part_dconfig['service'] = ''
            return new_part_dconfig

        list_vprns = []
        dict_vprns = {}
        re_vprns = re.compile(
            '^((?P<space>\s+)(?P<name>vprn\s+(?P<num>\d+)\s+.*?create)(?P<content>.*?)^(?P=space)exit)',
            re.MULTILINE | re.DOTALL)
        service_content = founds.group(3)
        # print(type(service_content))
        list_vprns = re_vprns.finditer(service_content)
        if list_vprns != []:
            for founds_vprn in list_vprns:
                num_vprn = founds_vprn.group('num')
                single_vprn = {'name': founds_vprn.group('name'),
                               'num': num_vprn,
                               'content': founds_vprn.group('content'),
                               'local_dhcp_servers': {},
                               'type': 'local_dhcp_servers'
                               }
                list_locserver = []
                re_lserver = re.compile(
                    '^((?P<space>\s+)(local-dhcp-server\s+(?P<name_s>\S+)\s+.*?create)(?P<content>.*?)^(?P=space)exit)',
                    re.MULTILINE | re.DOTALL)
                list_locserver = re_lserver.finditer(single_vprn['content'])
                if list_locserver != []:
                    for founds_lserver in list_locserver:
                        name_s = founds_lserver.group('name_s')
                        l_space = founds_lserver.group('space')
                        single_vprn['local_dhcp_servers'][name_s] = self.parse_local_server(founds_lserver.group('content'),
                                                                                       name_s, l_space)

                dict_vprns[num_vprn] = single_vprn

        new_part_dconfig['service'] = dict_vprns
        return new_part_dconfig

    def change_over_dconfig(self, dconfig):
        for header, content in (dconfig).items():
            if 'echo "Port Configuration"' in header:
                content = self.echo_port_conf_to_dict_N(content, header)
            elif 'echo "LAG Configuration"' in header:
                content = self.echo_lag_conf_to_dict_N(content, header)
            elif 'echo "Service Configuration"' in header:
                content = self.echo_service_conf_to_dict_N(content, header)
            elif 'echo "QoS Policy Configuration"' in header:
                content = self.echo_qos_policy_conf_to_dict(content, header)
            elif 'echo "Filter Match lists Configuration"' in header:
                content = self.echo_filter_match_lists_conf_to_dict(content, header)
            elif 'echo "Local DHCP Server (Services) Configuration"' in header:
                content = self.echo_local_DHCP_Server_services_conf_to_dict(content, header)
            elif 'echo "Router (Network Side) Configuration"' in header:
                content = self.echo_router_network_side_conf_to_dict(content, header)
            dconfig[header] = content
        return dconfig

        # WILL BE POINT OF ENTRY TO PROGRAMM



def converter(dlocal_d_config):

    def get_default_dict():
        default_dict = {'cfg': "", 'name': "", 'type': '', 'num': '', 'mode': None, 'giface': None, 'desc': '', 'shut': 0,
                        'addr': None, 'addrv6': None, 'secondary': [], 'qinq': None, 'mtu': '', 'res_optimization': 0,
                        'port_mode': '', 'sap':  None, 'dhcp_v4': None, 'dhcp_v6': None, 'qos_out': '0', 'qos_in': '10',
                        'acl_out': None, 'acl_in': None}

        return default_dict

    def set_default_value(data):
        default_dict = get_default_dict()

        for pol in default_dict.keys():
            if data.get(pol) is None:
                data[pol] = default_dict[pol]

    def lag_converter(ifaces, part_config):
        # if config.get('echo "LAG Configuration"') is not None:
        for i in part_config:
            # print(i)
            ifaces[i] = {}
            ifaces[i]['name'] = i
            ifaces[i]['type'], ifaces[i]['num'] = i.split(" ")
            ifaces[i]['desc'] = part_config[i]['description']
            ifaces[i]['qinq'] = part_config[i]['qinq_type']
            ifaces[i]['port_mode'] = part_config[i]['mode']
            ifaces[i]['cfg'] = i + "    " + part_config[i]['content']
            ifaces[i]['port_mode'] = part_config[i]['mode']
            ifaces[i]['res_optimization'] = part_config[i]['res_optimization']
            set_default_value(ifaces[i])

    def port_converter(ifaces, part_config):
        # if config.get('echo "Port Configuration"') is not None:
        for i in part_config:  # todo проверка
            # print(i)
            ifaces[i] = {}
            ifaces[i]['name'] = i
            # вначале перегоняем те параметры которые уже знаеи
            ifaces[i]['qinq'] = part_config[i]['qinq_type']
            ifaces[i]['port_mode'] = part_config[i]['mode']
            ifaces[i]['cfg'] = i + "    " + part_config[i]['content']
            ifaces[i]['shut'] = 1 if part_config[i]['shut'] == 'yes' else 0
            ifaces[i]['desc'] = part_config[i]['description']
            ifaces[i]['type'] = part_config[i]['type']
            suschn , ifaces[i]['num'] = i.split(" ")
            set_default_value(ifaces[i])

    def supscriber_converter(ifaces, part_config):
        # if config.get('echo "Service Configuration"') is not None:
        for num_vprn, vprn_content in part_config.items():
            #если будут исключения по vprn то сюда
            # if num_vprn not in ['3', '100', '120', '40018', '40045']:
            #     continue
            for si_name, si_content in vprn_content['setap_content']['subscriber_interfaces'].items():
                #если будут исключения по саб-интерфейсам то сюда
                # if '' not in si_name:
                #     continue
                name = 'interface "' + si_name + '"'
                ifaces[name] = {}

                ifaces[name]['name'] = name
                ifaces[name]['cfg'] = si_content['content']
                ifaces[name]['type'] = si_content['type']
                ifaces[name]['num'] = '"' + si_name + '"'
                ifaces[name]['desc'] = si_content['description']
                ifaces[name]['shut'] = si_content['shut']


                set_default_value(ifaces[name])

                group_interface_converter(ifaces, si_content['group_interfaces'])

    def group_interface_converter(ifaces, part_config):
        for gi_name, gi_content in part_config.items():
            #если будут исключения по гроуп-интерфейсам то сюда
            # if '' not in gi_name:
            #     continue
            name = "group-interface " + gi_name
            ifaces[name] = {}
            ifaces[name]['name'] = "group-interface " + gi_name
            ifaces[name]['type'] = gi_content['type']
            ifaces[name]['num'] = gi_name
            ifaces[name]['desc'] = gi_content['description']
            ifaces[name]['cfg'] = ifaces[name]['name'] + " create description \"" + gi_name + '"'
            set_default_value(ifaces[name])

    def interface_converter(ifaces, part_config):
        default_dict = get_default_dict()
        # if config.get('echo "Service Configuration"') is not None:
        for num_vprn, vprn_content in (part_config).items():
            for si_name, si_content in vprn_content['setap_content']['interfaces'].items():
                if '' not in si_name:
                    continue

                name = "interface \"" + si_name + '"'
                ifaces[name] = {'name': name,
                                'type': si_content['type'],
                                'num': '"' + si_name + '"',
                                'desc': si_content['description'],
                                'cfg': vprn_content['setap_content']['interfaces'][si_name]['content'],
                                #значения по умолчанию
                                'addr': default_dict['qos_out'],
                                'qos_out': default_dict['qos_out'],
                                'qos_in': default_dict['qos_in'],
                                'sap': default_dict['sap'],
                                'mode': default_dict['mode']
                                }
                #фактические значения если есть
                if vprn_content['setap_content']['interfaces'][si_name]['addr_v4'].get('ipv4_address') is not None:
                    ifaces[name]['addr'] = vprn_content['setap_content']['interfaces'][si_name]['addr_v4']['ipv4_address']
                if vprn_content['setap_content']['interfaces'][si_name]['addr_v6'].get('ipv6_address') is not None:
                    ifaces[name]['addrv6'] = vprn_content['setap_content']['interfaces'][si_name]['addr_v6']['ipv6_address']
                if vprn_content['setap_content']['interfaces'][si_name].get('qos_out') is not None:
                    ifaces[name]['qos_out'] = vprn_content['setap_content']['interfaces'][si_name]['qos_out']
                if vprn_content['setap_content']['interfaces'][si_name].get('qos_out') is not None:
                    ifaces[name]['qos_in'] = vprn_content['setap_content']['interfaces'][si_name]['qos_in']
                if vprn_content['setap_content']['interfaces'][si_name].get('sap') is not None:
                    ifaces[name]['sap'] = vprn_content['setap_content']['interfaces'][si_name]['sap']
                # ifaces[name]['num'] = ifaces[name]['addr']
                #установка если где то не заполнено - то значения по умолчанию что бы все проверяемые ключи присутствовали
                set_default_value(ifaces[name])


    ifaces = {}
    config = dlocal_d_config
    # переформатируем порты
    try: port_converter(ifaces, config['echo "Port Configuration"']['ports'])
    except Exception as ex: print("Error, %s" %ex)
    try: lag_converter(ifaces, config['echo "LAG Configuration"']['lags'])
    except Exception as ex: print("Error, %s" %ex)
    try: supscriber_converter(ifaces, config['echo "Service Configuration"']['service']['vprns'])
    except Exception as ex: print("Error, %s" %ex)
    try: interface_converter(ifaces, config['echo "Service Configuration"']['service']['vprns'])
    except Exception as ex: print("Error, %s" %ex)
    try: interface_converter(ifaces, config['echo "Router (Network Side) Configuration"']['router_base'])
    except Exception as ex: print("Error, %s" %ex)

    return ifaces

if __name__ == "__main__":

    #For example, used only with import
    Struct = Main_parse()
    with open('config_bsr_01_barnaul') as local_file:
        Main_parse.set_config(local_file)
    Main_parse.d_config = Main_parse.d_parse_config_N(Main_parse.config)
    Main_parse.d_config = Main_parse.change_over_dconfig(Main_parse.d_config)  # changeover d_config



    # print(dlocal_d_config['current']['echo "Service Configuration"']['service']['vprns']['100']['setap_content']['static_route_entry']['5.166.92.0/22']['preference'])
    #print local_config
