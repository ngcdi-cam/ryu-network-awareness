# Copyright (C) 2016 Li Cheng at Beijing University of Posts
# and Telecommunications. www.muzixing.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import copy
from operator import attrgetter
from ryu import cfg
from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from . import setting
from . import mininet_rest_client


CONF = cfg.CONF


class NetworkMonitor(app_manager.RyuApp):
    """
        NetworkMonitor is a Ryu app for collecting traffic information.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkMonitor, self).__init__(*args, **kwargs)
        self.name = 'monitor'
        self.datapaths = {}
        self.port_stats = {}
        self.port_speed = {}
        self.flow_stats = {}
        self.flow_speed = {}
        self.stats = {'flow': {}, 'port': {}}
        self.last_flows = {}
        self.bandwidth_stats_pretty = []
        self.port_features = {}
        self.free_bandwidth = {}
        self.awareness = lookup_service_brick('awareness')
        self.graph = None
        self.capabilities = None
        self.best_paths = None

        if setting.BANDWIDTH_SOURCE == "mininet":
            self.mininet_rest_client = mininet_rest_client.MininetRestClient(
                base_url=setting.MININET_REST_BASE_URL)
            self.mininet_link_bandwidths = {}

        # Start to green thread to monitor traffic and calculating
        # free bandwidth of links respectively.
        self.monitor_thread = hub.spawn(self._monitor)
        self.save_freebandwidth_thread = hub.spawn(self._save_bw_graph)

        self.flows = []

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
            Record datapath's info
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        """
            Main entry method of monitoring traffic.
        """
        while CONF.weight == 'bw' or CONF.weight == 'all':
            #self.stats['flow'] = {}
            #self.stats['port'] = {}

            if setting.BANDWIDTH_SOURCE == "mininet":
                self.mininet_link_bandwidths = self.mininet_rest_client.get_link_bandwidths()

            for dp in list(self.datapaths.values()):
                self.port_features.setdefault(dp.id, {})
                self._request_stats(dp)
                # refresh data.
                self.capabilities = None
                self.best_paths = None
            hub.sleep(setting.MONITOR_PERIOD)
            if self.stats['flow'] or self.stats['port']:
                self.show_stat('flow')
                self.show_stat('port')
                hub.sleep(1)

    def _save_bw_graph(self):
        """
            Save bandwidth data into networkx graph object.
        """
        while CONF.weight == 'bw' or CONF.weight == 'all':
            self.graph = self.create_bw_graph(self.free_bandwidth)
            self.logger.debug("save_freebandwidth")
            #hub.sleep(setting.MONITOR_PERIOD)
            hub.sleep(10)

    def _request_stats(self, datapath):
        """
            Sending request msg to datapath
        """
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def get_min_bw_of_links(self, graph, path, exclusion=None, min_bw=setting.MAX_CAPACITY):
        """
            Get the free bandwidth of the path specified
        """

        _len = len(path)
        if _len > 1:
            minimal_band_width = min_bw
            for i in range(_len-1):
                pre, curr = path[i], path[i+1]
                if 'free_bandwidth' in graph[pre][curr]:
                    bw = graph[pre][curr]['free_bandwidth']

                    self.logger.info('get_min_bw_of_links(): Raw free bw = {}'.format(bw))
                    # self.logger.info('get_min_bw_of_links(): last_flows = {}'.format(self.last_flows))
                    if exclusion is not None and curr in self.last_flows:
                        src_ip, dst_ip = exclusion
                        _, curr_port = self.awareness.link_to_port[(pre, curr)]

                        self.logger.info('get_min_bw_of_links(): src_ip = {}, dst_ip = {}, curr_port = {}'.format(src_ip, dst_ip, curr_port))

                        for flow in self.last_flows[curr]:
                            self.logger.info(
                                'get_min_bw_of_links(): flow info: {}'.format(flow.match))

                            
                            if flow.match.get('in_port') != curr_port or flow.match.get('ipv4_src') != src_ip or flow.match.get('ipv4_dst') != dst_ip:
                                continue

                            flow_speed_history = self.flow_speed[curr][
                                (flow.match.get('in_port'),
                                 flow.match.get('ipv4_dst'),
                                 flow.instructions[0].actions[0].port)]
                            
                            if len(flow_speed_history) < 2:
                                self.logger.info('get_min_bw_of_links(): No enough speed history entries')
                                continue
                            
                            flow_speed = abs(flow_speed_history[-2]) * 8 / 10 ** 3
                            self.logger.info(
                                'get_min_bw_of_links(): Found matching flow, speed = {}'.format(flow_speed))
                            bw += flow_speed
                            break

                    self.logger.info('get_min_bw_of_links(): Free bw = {}'.format(bw))

                    minimal_band_width = min(bw, minimal_band_width)
                else:
                    continue
            return minimal_band_width
        return min_bw

    def map_bw_to_score(self, bw: float):
        return bw / 1000.0

    def get_best_path_by_bw(self, graph, paths):
        """
            Get best path by comparing paths.
        """
        capabilities = {}
        best_paths = copy.deepcopy(paths)

        for src in paths:
            for dst in paths[src]:
                if src == dst:
                    best_paths[src][src] = [src]
                    capabilities.setdefault(src, {src: setting.MAX_CAPACITY})
                    capabilities[src][src] = setting.MAX_CAPACITY
                    continue
                max_bw_of_paths = 0
                best_path = paths[src][dst][0]
                for path in paths[src][dst]:
                    min_bw = self.get_min_bw_of_links(graph, path)
                    if min_bw > max_bw_of_paths:
                        max_bw_of_paths = min_bw
                        best_path = path

                best_paths[src][dst] = best_path
                capabilities.setdefault(src, {dst: max_bw_of_paths})
                capabilities[src][dst] = max_bw_of_paths
        self.capabilities = capabilities
        self.best_paths = best_paths
        return capabilities, best_paths

    def create_bw_graph(self, bw_dict):
        """
            Save bandwidth data into networkx graph object.
        """
        try:
            graph = self.awareness.graph
            link_to_port = self.awareness.link_to_port
            for link in link_to_port:
                (src_dpid, dst_dpid) = link
                (src_port, dst_port) = link_to_port[link]
                if src_dpid in bw_dict and dst_dpid in bw_dict:
                    bw_src = bw_dict[src_dpid][src_port]
                    bw_dst = bw_dict[dst_dpid][dst_port]
                    free_bw = min(bw_src, bw_dst)
                    # add key:value of bandwidth into graph.
                    graph[src_dpid][dst_dpid]['free_bandwidth'] = free_bw
                else:
                    graph[src_dpid][dst_dpid]['free_bandwidth'] = 0

                if src_dpid in self.port_features and src_port in self.port_features[src_dpid] \
                        and dst_dpid in self.port_features and dst_port in self.port_features[dst_dpid]:
                    bw_src = self.port_features[src_dpid][src_port][2]
                    bw_dst = self.port_features[dst_dpid][dst_port][2]
                    bandwidth = min(bw_src, bw_dst)
                    graph[src_dpid][dst_dpid]['bandwidth'] = bandwidth
                else:
                    graph[src_dpid][dst_dpid]['bandwidth'] = 0

                if (src_dpid, src_port) in self.port_speed and (dst_dpid, dst_port) in self.port_speed:
                    throughput_src = self.port_speed[(
                        src_dpid, src_port)][-1] * 8 / 10 ** 3
                    throughput_dst = self.port_speed[(
                        dst_dpid, dst_port)][-1] * 8 / 10 ** 3
                    throughput = min(throughput_src, throughput_dst)
                    graph[src_dpid][dst_dpid]['throughput'] = throughput
                else:
                    graph[src_dpid][dst_dpid]['throughput'] = 0
            return graph
        except:
            self.logger.info("Create bw graph exception")
            if self.awareness is None:
                self.awareness = lookup_service_brick('awareness')
            return self.awareness.graph

    def _save_freebandwidth(self, dpid, port_no, speed):
        # Calculate free bandwidth of port and save it.
        port_state = self.port_features.get(dpid).get(port_no)
        if port_state:
            capacity = port_state[2]
            curr_bw = self._get_free_bw(capacity, speed)
            self.free_bandwidth[dpid].setdefault(port_no, None)
            self.free_bandwidth[dpid][port_no] = curr_bw
        else:
            self.logger.info("Fail in getting port state")

    def _save_stats(self, _dict, key, value, length):
        if key not in _dict:
            _dict[key] = []
        _dict[key].append(value)

        if len(_dict[key]) > length:
            _dict[key].pop(0)

    def _get_speed(self, now, pre, period):
        if period:
            return (now - pre) / (period)
        else:
            return 0

    def _get_free_bw(self, capacity, speed):
        # BW: kbps
        return max(capacity - speed * 8/10**3, 0)

    def _get_time(self, sec, nsec):
        return sec + nsec / (10 ** 9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
            Save flow stats reply info into self.flow_stats.
            Calculate flow speed and Save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        # self.logger.info('_flow_stats_reply_handler(): flows = {}'.format(self.stats['flow'].get(dpid)))
        if dpid in self.stats['flow']: 
            self.last_flows[dpid] = copy.deepcopy(self.stats['flow'][dpid])
        self.stats['flow'][dpid] = body
        self.flow_stats.setdefault(dpid, {})
        self.flow_speed.setdefault(dpid, {})
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match.get('in_port'),
                                             flow.match.get('ipv4_dst'))):
            key = (stat.match['in_port'],  stat.match.get('ipv4_dst'),
                   stat.instructions[0].actions[0].port)
            value = (stat.packet_count, stat.byte_count,
                     stat.duration_sec, stat.duration_nsec)
            self._save_stats(self.flow_stats[dpid], key, value, 5)

            # Get flow's speed.
            pre = 0
            #period = setting.MONITOR_PERIOD
            period = 10
            tmp = self.flow_stats[dpid][key]
            if len(tmp) > 1:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])

            speed = self._get_speed(self.flow_stats[dpid][key][-1][1],
                                    pre, period)

            self._save_stats(self.flow_speed[dpid], key, speed, 5)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
            Save port's stats info
            Calculate port's speed and save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['port'][dpid] = body
        self.free_bandwidth.setdefault(dpid, {})

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
                         stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats, key, value, 5)

                # Get port speed.
                pre = 0
                #period = setting.MONITOR_PERIOD
                period = 10
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][0] + tmp[-2][1]
                    period = self._get_period(tmp[-1][3], tmp[-1][4],
                                              tmp[-2][3], tmp[-2][4])

                speed = self._get_speed(
                    self.port_stats[key][-1][0] + self.port_stats[key][-1][1],
                    pre, period)

                self._save_stats(self.port_speed, key, speed, 5)
                self._save_freebandwidth(dpid, port_no, speed)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """
            Save port description info.
        """
        msg = ev.msg
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        config_dict = {ofproto.OFPPC_PORT_DOWN: "Down",
                       ofproto.OFPPC_NO_RECV: "No Recv",
                       ofproto.OFPPC_NO_FWD: "No Forward",
                       ofproto.OFPPC_NO_PACKET_IN: "No Packet-in"}

        state_dict = {ofproto.OFPPS_LINK_DOWN: "Down",
                      ofproto.OFPPS_BLOCKED: "Blocked",
                      ofproto.OFPPS_LIVE: "Live"}

        ports = []
        for p in ev.msg.body:
            ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                         'state=0x%08x curr=0x%08x advertised=0x%08x '
                         'supported=0x%08x peer=0x%08x curr_speed=%d '
                         'max_speed=%d' %
                         (p.port_no, p.hw_addr,
                          p.name, p.config,
                          p.state, p.curr, p.advertised,
                          p.supported, p.peer, p.curr_speed,
                          p.max_speed))

            if p.config in config_dict:
                config = config_dict[p.config]
            else:
                config = "up"

            if p.state in state_dict:
                state = state_dict[p.state]
            else:
                state = "up"

            if setting.BANDWIDTH_SOURCE == "mininet":
                speed = self.mininet_link_bandwidths.get(
                    p.name.decode('ascii'), p.curr_speed)
            else:
                speed = p.curr_speed

            port_feature = (config, state, speed)
            self.port_features[dpid][p.port_no] = port_feature
        #self.logger.info("----------------- ports -----------------")
        # self.logger.info("\n".join(ports))

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        """
            Handle the port status changed event.
        """
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        reason_dict = {ofproto.OFPPR_ADD: "added",
                       ofproto.OFPPR_DELETE: "deleted",
                       ofproto.OFPPR_MODIFY: "modified", }

        if reason in reason_dict:

            print("switch%d: port %s %s" %
                  (dpid, reason_dict[reason], port_no))
        else:
            print("switch%d: Illeagal port state %s %s" % (port_no, reason))

    def show_stat(self, type):
        '''
            Show statistics info according to data type.
            type: 'port' 'flow'
        '''
        if setting.TOSHOW is False:
            return

        bodys = self.stats[type]

        if(type == 'flow'):
            self.flows.clear()
            print('datapath         ''   in-port        ip-dst      '
                  'out-port packets  bytes  flow-speed(B/s)')
            print('---------------- ''  -------- ----------------- '
                  '-------- -------- -------- -----------')
            for dpid in list(bodys.keys()):
                for stat in sorted(
                    [flow for flow in bodys[dpid] if flow.priority == 1],
                    key=lambda flow: (flow.match.get('in_port'),
                                      flow.match.get('ipv4_dst'))):
                    print(('%016x %8x %17s %8x %8d %8d %8.1f' % (
                        dpid,
                        stat.match['in_port'], stat.match.get('ipv4_dst'),
                        stat.instructions[0].actions[0].port,
                        stat.packet_count, stat.byte_count,
                        abs(self.flow_speed[dpid][
                            (stat.match.get('in_port'),
                             stat.match.get('ipv4_dst'),
                             stat.instructions[0].actions[0].port)][-1]))))
                    
                    self.flows.append({
                        'dpid': dpid,
                        'in_port': stat.match['in_port'],
                        'ip_dst':  stat.match.get('ipv4_dst'),
                        'ip_src':  stat.match.get('ipv4_src'),
                        'out_port': stat.instructions[0].actions[0].port,
                        'packets': stat.packet_count,
                        'bytes': stat.byte_count
                    })
            print('\n')

        if(type == 'port'):
            print('datapath             port   ''rx-pkts  rx-bytes rx-error '
                  'tx-pkts  tx-bytes tx-error  port-speed(B/s)'
                  ' current-capacity(Kbps)  '
                  'port-stat   link-stat')
            print('----------------   -------- ''-------- -------- -------- '
                  '-------- -------- -------- '
                  '----------------  ----------------   '
                  '   -----------    -----------')
            format = '%016x %8x %8d %8d %8d %8d %8d %8d %8.1f %16d %16s %16s'
            self.bandwidth_stats_pretty.clear()
            for dpid in list(bodys.keys()):
                for stat in sorted(bodys[dpid], key=attrgetter('port_no')):
                    if stat.port_no != ofproto_v1_3.OFPP_LOCAL:
                        self.bandwidth_stats_pretty.append({
                            'dpid': dpid,
                            'port_no': stat.port_no,
                            'rx_packets': stat.rx_packets,
                            'rx_bytes': stat.rx_bytes,
                            'rx_errors': stat.rx_errors,
                            'tx_packets': stat.tx_packets,
                            'tx_bytes': stat.tx_bytes,
                            'tx_errors': stat.tx_errors,
                            'speed': abs(self.port_speed[(dpid, stat.port_no)][-1]),
                            'bandwidth': self.port_features[dpid][stat.port_no][2],
                            'port_status': self.port_features[dpid][stat.port_no][0],
                            'link_status': self.port_features[dpid][stat.port_no][1]
                        })

                        print((format % (
                            dpid, stat.port_no,
                            stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                            stat.tx_packets, stat.tx_bytes, stat.tx_errors,
                            abs(self.port_speed[(dpid, stat.port_no)][-1]),
                            self.port_features[dpid][stat.port_no][2],
                            self.port_features[dpid][stat.port_no][0],
                            self.port_features[dpid][stat.port_no][1])))
            print('\n')
