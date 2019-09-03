#!/usr/bin/python

import argparse
import traceback
import requests


def dump(it):
    if arguments['debug']:
        print(it)


def build_node_url():
    url = "%(addr)s/v1/health/node/%(NODE)s?dc=%(DC)s" % arguments
    return url


def get_json_from_url(url, headers=None, cert=None):
    dump("url: {0}".format(url))
    dump("headers: {0}".format(headers))
    dump("cert: {0}".format(cert))
    r = requests.get(url, headers=headers, cert=cert)
    dump("Response: " + r.text)
    dump("Status code: " + str(r.status_code))
    r.raise_for_status()
    return r.json()


def print_check(check):
    print("> %(Node)s:%(ServiceName)s:%(Name)s:%(CheckID)s:%(Status)s" % check)


def process_failing(checks):
    def check_output(x):
        return x["Name"] + ":" + x["Output"]

    filters = map(lambda field: lambda x: arguments[field] is None or x[field] == arguments[field],
                  ['CheckID', 'ServiceName']
                  )

    filtered = list(filter(lambda x: all(f(x) for f in filters), checks))
    passing = list(filter(lambda x: x['Status'] == 'passing', filtered))
    warning = list(filter(lambda x: x['Status'] == 'warning', filtered))
    critical = list(filter(lambda x: x['Status'] == 'critical', filtered))

    if len(checks) == 0:
        print("There is no matching node!")
        return 1

    if len(filtered) == 0:
        print("There is no matching check!")
        return 1

    if len(critical):
        print("|".join(map(check_output, critical)))
        for check in critical:
            print_check(check)
    if len(warning):
        print("|".join(map(check_output, warning)))
        for check in warning:
            print_check(check)
    if len(passing):
        print("Passing: %d" % (len(passing)))
        for check in passing:
            print_check(check)

    return 2 if len(critical) else 1 if len(warning) else 0


def prepare_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cert', metavar='FILE', default=None, type=str, help='client certificate')
    parser.add_argument('--key', metavar='FILE', default=None, type=str, help='client key')
    parser.add_argument('--token', default=None, type=str, help='token')
    parser.add_argument('--debug', action='store_true', help='debug output')

    subparsers = parser.add_subparsers(help='check individual node')
    node_parser = subparsers.add_parser('node')
    node_parser.add_argument('NODE', metavar='NODE', help='the consul node_name')
    node_parser.add_argument('DC', metavar='DC', help='the consul datacenter')
    node_parser.add_argument('--addr', default='http://localhost:8500',
                             help='consul address [default: http://localhost:8500]')
    node_parser.add_argument('--CheckID', default=None, type=str, help='CheckID matcher')
    node_parser.add_argument('--ServiceName', default=None, type=str, help='ServiceName matcher')

    return parser.parse_args().__dict__


if __name__ == '__main__':
    try:
        arguments = prepare_args()

        url = build_node_url()
        headers = None
        if arguments['token'] is not None:
            headers = {'X-Consul-Token': arguments['token']}
        cert = None
        if arguments['cert'] is not None or arguments['key'] is not None:
            if None in [arguments['cert'], arguments['key']]:
                raise ValueError('both cert and key arguments required')
            cert = (arguments['cert'], arguments['key'])
        json_response = get_json_from_url(url, headers=headers, cert=cert)
        exit(process_failing(json_response))
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        exit(3)
