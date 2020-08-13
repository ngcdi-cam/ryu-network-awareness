from ryu.app.wsgi import ControllerBase, WSGIApplication, Response, Request, route
from ryu.base import app_manager
import json
import networkx
import simplejson


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
        body = json.dumps({
            'graph': list(map(lambda x: dict(src=x[0], dst=x[1], **x[2]), networkx.convert.to_edgelist(self.awareness.graph)))
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

    @route(app_name, '/awareness/weights/switches', methods=['POST'])
    def set_switch_weights(self, req, **kwargs):
        try:
            switches = req.json.get('switches')
            assert type(switches) == dict
            for (k, v) in switches.items():
                assert type(k) == str
                assert type(v) == float or type(v) == int

            switches = {int(k): v for (k, v) in switches.items()}
            print(switches)
            self.shortest_forwarding.switch_weights = switches
        except (AssertionError, KeyError, simplejson.errors.JSONDecodeError) as e:
            return bad_request_response(e)
        return success_response()

    @route(app_name, '/awareness/weights/default_metric', methods=['GET'])
    def get_default_metric_weights(self, req, **kwargs):
        body = json.dumps({
            'default_metric': self.shortest_forwarding.default_metric_weights
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/weights/default_metric', methods=['POST'])
    def set_default_metric_weights(self, req, **kwargs):
        try:
            default_metric = req.json.get('default_metric')
            assert type(default_metric) == dict
            for (k, v) in default_metric.items():
                assert type(k) == str
                assert type(v) == float or type(v) == int
            self.shortest_forwarding.default_metric_weights = default_metric
        except Exception as e:
            return bad_request_response(e)
        return success_response()

    @route(app_name, '/awareness/services', methods=['GET'])
    def get_services(self, req, **kwargs):
        body = json.dumps({
            'services': self.shortest_forwarding.services
        })
        return Response(content_type='application/json', body=body)

    @route(app_name, '/awareness/services', methods=['POST'])
    def set_services(self, req, **kwargs):
        try:
            services = req.json.get('services')
            assert type(services) is list

            self.shortest_forwarding.services.clear()

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
                self.shortest_forwarding.services.append(
                    dict(id=id, src=src, dst=dst, weights=weights, enabled=enabled))
                
        except Exception as e:
            return bad_request_response(e)
        return success_response()
