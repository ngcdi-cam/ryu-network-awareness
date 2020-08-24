from ryu.app.wsgi import ControllerBase, WSGIApplication, Response, Request, route
from ryu.base import app_manager
import json
import networkx

def bad_request_response(e: Exception):
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

    @route(app_name, '/awareness/stats', methods=['GET'])
    def get_stats(self, req, **kwargs):
        graph = []

        for edge in networkx.convert.to_edgelist(self.awareness.graph):
            src, dst, metrics = edge
            if src >= dst:
                continue
                
            src_port, dst_port = self.awareness.link_to_port.get((src, dst), (-1, -1))
            graph.append(dict(src=src, dst=dst, metrics=metrics, src_port=src_port, dst_port=dst_port))

        body = json.dumps({
            'graph': graph
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/links', methods=['GET'])
    def get_links(self, req, **kwargs):
        body = json.dumps({
            'links':  list(
                filter(
                    lambda link: link['src'] <= link['dst'], 
                    map(
                        lambda item: 
                            {'src': item[0][0], 'dst': item[0][1], 'src_port': item[1][0], 'dst_port': item[1][1]}, 
                        self.awareness.link_to_port.items()
                    )
                )
            )
        })
        return Response(content_type='application/json', body=body)
    
    @route(app_name, '/awareness/flows', methods=['GET'])
    def get_flows(self, req, **kwargs):
        body = json.dumps({
            'flows': self.monitor.flows
        })
        return Response(content_type='application/json', body=body)
    
    @route(app_name, '/awareness/active_paths', methods=['GET'])
    def get_paths(self, req, **kwargs):
        paths_dict = self.shortest_forwarding.active_paths
        paths = []
        for src in paths_dict:
            for dst in paths_dict[src]:
                path, timestamp = paths_dict[src][dst]
                paths.append({'src': src, 'dst': dst, 'timestamp': timestamp, 'path': path})
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

        except (AssertionError, KeyError, simplejson.errors.JSONDecodeError) as e:
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
                assert type(src) is int
                dst = service['dst']
                assert type(dst) is int
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
                self.shortest_forwarding.services = services_dict
            elif req.method == 'PATCH':
                self.shortest_forwarding.services.update(services_dict)
            else:
                assert False

        except Exception as e:
            return bad_request_response(e)
        return success_response()
