from ryu.app.wsgi import ControllerBase, WSGIApplication, Response, Request, route
from ryu.base import app_manager
import json
import networkx
import traceback
from collections import OrderedDict

def bad_request_response(e: Exception):
    print("Bad request: " + str(e))
    traceback.print_exc()
    body = json.dumps({
        'error': True,
        'msg': repr(e)
    })
    return Response(content_type='application/json', body=body, status=400)


def success_response():
    body = json.dumps({
        'success': True
    })
    return Response(content_type='application/json', body=body)


class NetworkAwarenessRestfulAPI(app_manager.RyuApp):
    _CONTEXTS = {
        'wsgi': WSGIApplication,
    }

    def __init__(self, *args, **kwargs):
        super(NetworkAwarenessRestfulAPI, self).__init__(*args, **kwargs)

        wsgi = kwargs['wsgi']
        wsgi.register(NetworkAwarenessRestfulController)


class NetworkAwarenessRestfulController(ControllerBase):
    app_name = 'awareness'

    def __init__(self, req, link, data, **config):
        super(NetworkAwarenessRestfulController, self).__init__(
            req, link, data, **config)
        self.monitor = app_manager.lookup_service_brick('monitor')
        self.delay_detector = app_manager.lookup_service_brick('delaydetector')
        self.awareness = app_manager.lookup_service_brick('awareness')
        self.shortest_forwarding = app_manager.lookup_service_brick(
            'shortest_forwarding')

    @route(app_name, '/awareness/stats/raw_latency', methods=['GET'])
    def get_raw_delay(self, req, **kwargs):
        body = json.dumps({
            'latency': self.delay_detector.latency_stats_pretty
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/stats/raw_throughput', methods=['GET'])
    def get_raw_throughput(self, req, **kwargs):
        body = json.dumps({
            'throughput': self.monitor.bandwidth_stats_pretty
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/stats/raw_monitor', methods=['GET'])
    def get_raw_monitor(self, req, **kwargs):
        body = json.dumps({
            'throughput': self.monitor.stats
        }, default=lambda o: '<not serializable>')
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/stats', methods=['GET'])
    def get_stats(self, req, **kwargs):
        graph = []

        for edge in networkx.convert.to_edgelist(self.awareness.graph):
            src, dst, metrics = edge
            if src >= dst:
                continue

            src_port, dst_port = self.awareness.link_to_port.get(
                (src, dst), (-1, -1))
            graph.append(dict(src=src, dst=dst, metrics=metrics,
                              src_port=src_port, dst_port=dst_port))

        body = json.dumps({
            'graph': graph
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/stats/{src}/{dst}', methods=['GET'])
    def get_stats_specific_src_dst(self, req, src, dst, **kwargs):
        try:
            src = int(src)
            dst = int(dst)
            metrics = self.awareness.graph[src][dst]
            src_port, dst_port = self.awareness.link_to_port.get(
                (src, dst), (-1, -1))
            body = json.dumps({
                'src': src,
                'dst': dst,
                'src_port': src_port,
                'dst_port': dst_port,
                'metrics': metrics
            })
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return bad_request_response(e)

    @route(app_name, '/awareness/stats/{src}', methods=['GET'])
    def get_stats_specific_src(self, req, src, **kwargs):
        try:
            filter = 'filter' in req.params  # filter links where dst > src
            src = int(src)
            links = []
            for dst, metrics in self.awareness.graph[src].items():
                if filter and src > dst:
                    continue
                src_port, dst_port = self.awareness.link_to_port.get(
                    (src, dst), (-1, -1))
                links.append({
                    'src': src,
                    'dst': dst,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'metrics': metrics
                })
            body = json.dumps({'graph': links})
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return bad_request_response(e)

    @route(app_name, '/awareness/links', methods=['GET'])
    def get_links(self, req, **kwargs):
        body = json.dumps({
            'links':  list(
                filter(
                    lambda link: link['src'] <= link['dst'],
                    map(
                        lambda item:
                            {'src': item[0][0], 'dst': item[0][1],
                                'src_port': item[1][0], 'dst_port': item[1][1]},
                        self.awareness.link_to_port.items()
                    )
                )
            )
        })
        return Response(content_type='application/json', body=body)
    
    @route(app_name, '/awareness/path_info', methods=['POST'])
    def get_path_stats(self, req, **kwargs):
        req_obj = req.json

        weights = req_obj.get('weights', self.shortest_forwarding.default_metric_weights)
        assert type(weights) is dict
        for k, v in weights.items():
            assert type(k) is str
            assert type(v) is float
        
        stats = []
        src_dst_pairs = req_obj.get('src_dst_pairs')
        assert type(src_dst_pairs) is list
        
        for pair in src_dst_pairs:
            assert type(pair) is dict
            src = pair.get('src')
            assert type(src) is int
            dst = pair.get('dst')
            assert type(dst) is int
            src_ip = pair.get('src_ip')
            assert type(src_ip) is str
            dst_ip = pair.get('dst_ip')
            assert type(dst_ip) is str

            path, metric_values, score = self.shortest_forwarding.weight_model_all_get_path(src, dst, src_ip, dst_ip, weights)
            stats.append({
                'src': src,
                'dst': dst,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'path': path,
                'metrics': metric_values,
                'score': score
            })
        
        body = json.dumps({
            'stats': stats,
            'switch_weights': self.shortest_forwarding.switch_weights
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/access_table_entry_pinnings', methods=['PATCH'])
    def set_access_table_entry_pinnings(self, req, **kwargs):
        access_table = self.awareness.access_table
        # access_table = OrderedDict()
        pinnings = req.json.get('pinnings')
        assert type(pinnings) is list
        for pinning in pinnings:
            assert type(pinning) is dict
            t_ip = pinning.get('ip')
            assert type(t_ip) is str
            t_dpid = pinning.get('dpid')
            assert type(t_dpid) is int
            t_port = pinning.get('port')
            assert type(t_port) is int

            t_mac = None
            for (dpid, port), (ip, mac) in access_table.items():
                if ip == t_ip:
                    t_mac = mac
                    break

            assert t_mac is not None
            access_table[(t_dpid, t_port)] = (t_ip, t_mac)
            access_table.move_to_end((t_dpid, t_port), False)
        return success_response()

    @route(app_name, '/awareness/access_ports', methods=['GET'])
    def get_access_port(self, req, **kwargs):
        a = {}

        for k, v in self.awareness.access_ports.items():
            a[k] = list(v)
        
        body = json.dumps({
            'access_ports': a
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/access_table', methods=['GET'])
    def get_access_table(self, req, **kwargs):
        access_table = list(
            map(
                lambda x: {'host_ip': x[1][0], 'host_mac': x[1][1], 'dpid': x[0][0], 'port': x[0][1]},
                self.awareness.access_table.items()
            )
        )
        access_table_filtered = []
        for t in access_table:
            if t['port'] in self.awareness.access_ports.get(t['dpid']):
                access_table_filtered.append(t)
        
        body = json.dumps({
            'access_table': access_table_filtered
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/flows_raw', methods=['GET'])
    def get_flows(self, req, **kwargs):
        body = json.dumps({
            'flows': self.monitor.flows
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/flows/{dpid}', methods=['GET'])
    def get_flows_specific_dpid(self, req, dpid, **kwargs):
        filter = 'filter' in req.params
        dpid = int(dpid)
        flows_raw = self.monitor.stats['flow'].get(dpid)
        flows = []

        if flows_raw:
            for flow in flows_raw:
                if flow.priority != 1:
                    continue

                match = flow.match

                in_port = match.get('in_port')
                out_port = flow.instructions[0].actions[0].port

                src_ip = match.get('ipv4_src')
                dst_ip = match.get('ipv4_dst')

                throughput = abs(self.monitor.flow_speed[dpid][
                    (in_port,
                     match.get('ipv4_dst'),
                     out_port)][-1]) * 8 / 10 ** 3

                for (src_dpid, dst_dpid), (src_port, dst_port) in self.awareness.link_to_port.items():
                    if (src_dpid == dpid and out_port == src_port) or (dst_dpid == dpid and in_port == dst_port):
                        if filter and src_dpid > dst_dpid:
                            continue

                        flows.append({
                            'src_ip_dpid': self.awareness.get_host_location(src_ip)[0],
                            'dst_ip_dpid': self.awareness.get_host_location(dst_ip)[0],
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'src': src_dpid,
                            'dst': dst_dpid,
                            'dst_ip': dst_ip,
                            'src_ip': src_ip,
                            'throughput': throughput
                        })
        body = json.dumps({
            'flows': flows
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/active_paths', methods=['GET'])
    def get_paths(self, req, **kwargs):
        paths_dict = self.shortest_forwarding.active_paths
        paths = []
        for src in paths_dict:
            for dst in paths_dict[src]:
                path, timestamp = paths_dict[src][dst]
                paths.append(
                    {'src': src, 'dst': dst, 'timestamp': timestamp, 'path': path})
        body = json.dumps({
            'paths': paths
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/weights', methods=['GET'])
    def get_weights(self, req, **kwargs):
        body = json.dumps({
            'switches': self.shortest_forwarding.switch_weights,
            'default_metric': self.shortest_forwarding.default_metric_weights
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/weights/switches', methods=['GET'])
    def get_switch_weights(self, req, **kwargs):
        body = json.dumps({
            'switches': self.shortest_forwarding.switch_weights
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/weights/switches', methods=['POST', 'PUT', 'PATCH'])
    def set_switch_weights(self, req, **kwargs):
        try:
            switches = req.json.get('switches')
            assert type(switches) == dict
            for (k, v) in switches.items():
                assert type(k) is str
                assert type(v) is float or type(v) is int

            switches = {int(k): v for (k, v) in switches.items()}

            if req.method in ('POST', 'PUT'):
                self.shortest_forwarding.switch_weights = switches
            elif req.method == 'PATCH':
                self.shortest_forwarding.switch_weights.update(switches)
            else:
                assert False

        except (AssertionError, KeyError, json.JSONDecodeError) as e:
            return bad_request_response(e)
        return success_response()

    @route(app_name, '/awareness/weights/default_metrics', methods=['GET'])
    def get_default_metric_weights(self, req, **kwargs):
        body = json.dumps({
            'default_metrics': self.shortest_forwarding.default_metric_weights
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/weights/default_metrics', methods=['POST', 'PUT', 'PATCH'])
    def set_default_metric_weights(self, req, **kwargs):
        try:
            default_metric = req.json.get('default_metrics')
            assert type(default_metric) == dict
            for (k, v) in default_metric.items():
                assert type(k) is str
                assert type(v) is float or type(v) is int

            if req.method in ('POST', 'PUT'):
                self.shortest_forwarding.default_metric_weights = default_metric
            elif req.method == 'PATCH':
                self.shortest_forwarding.default_metric_weights.update(
                    default_metric)
            else:
                assert False

        except Exception as e:
            return bad_request_response(e)
        return success_response()

    @route(app_name, '/awareness/services', methods=['GET'])
    def get_services(self, req, **kwargs):
        body = json.dumps({
            'services': self.shortest_forwarding.services
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/services', methods=['POST', 'PUT', 'PATCH'])
    def set_services(self, req, **kwargs):
        try:
            services = req.json.get('services')
            assert type(services) is list

            services_dict = {}

            for service in services:
                id = service['id']
                assert type(id) is int
                src = service['src']
                assert type(src) is str
                dst = service['dst']
                assert type(dst) is str
                weights = service.get('weights', {})
                assert type(weights) is dict
                for (k, v) in weights.items():
                    assert type(k) is str
                    assert type(v) is float or type(v) is int

                enabled = service.get('enabled', True)

                assert type(enabled) is bool
                services_dict[id] = dict(
                    id=id, src=src, dst=dst, weights=weights, enabled=enabled)

            if req.method in ('POST', 'PUT'):
                print("service_dict is " + services_dict)
                self.shortest_forwarding.services = services_dict
            elif req.method == 'PATCH':
                self.shortest_forwarding.services.update(services_dict)
            else:
                assert False

        except Exception as e:
            return bad_request_response(e)
        return success_response()
