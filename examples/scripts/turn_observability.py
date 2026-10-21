#!/usr/bin/env python3
"""Real local TURN/exporter regression checks; standard library only."""
import concurrent.futures
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

from mobility_quota_flood import (
    A_USERNAME, A_REALM, A_NONCE, A_REQ_TRANSPORT, A_LIFETIME, A_ERROR,
    M_ALLOCATE, M_REFRESH, ALLOCATE_OK, REFRESH_OK, UDP_RELAY,
    challenge, make, parse, get, xact, errcode, recv_stun,
)

ROOT = Path(__file__).resolve().parents[2]
BINDIR = Path(sys.argv[1]).resolve()
FAMILIES = (
    'turn_quota_used', 'turn_quota_limit', 'turn_allocate_results_total',
    'turn_allocations_created_total', 'turn_allocations_closed_total',
    'turn_allocations_by_activity', 'turn_observability_snapshot_timestamp_seconds',
)


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_for(predicate, description, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(.1)
    raise AssertionError(description)


def samples(body):
    result = {}
    for line in body.splitlines():
        if line.startswith('#') or not line:
            continue
        match = re.fullmatch(r'([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})? ([^ ]+)', line)
        assert match, 'invalid sample line'
        name, labels, value = match.groups()
        if name not in FAMILIES:
            continue
        pairs = tuple(sorted((key, json.loads('"' + val + '"')) for key, val in
            re.findall(r'([a-z_]+)="((?:\\.|[^"\\])*)"', labels or '')))
        result[name, pairs] = float(value)
    return result


def value(data, name, **labels):
    return data[name, tuple(sorted(labels.items()))]


@contextlib.contextmanager
def server(extra=(), realms=(), known_realms=(), default='observed', slow_readers=False, tls=False):
    with tempfile.TemporaryDirectory(prefix='turn-observation-') as directory:
        directory = Path(directory)
        database = directory / 'users.db'
        with sqlite3.connect(database) as connection:
            connection.executescript((ROOT / 'turndb/schema.sql').read_text())
            for realm in known_realms:
                connection.execute('insert into turn_origin_to_realm values (?,?)',
                                   ('https://r' + str(len(realm)) + '-' + str(known_realms.index(realm)) + '.test', realm))
        turn_port, metrics_port = port(), port()
        command = [str(BINDIR / 'turnserver'), '-n', '--realm=' + default, '--user=user:pass',
                   '--db=' + str(database), '--pidfile=' + str(directory / 'turnserver.pid'),
                   '--listening-ip=127.0.0.1', '--relay-ip=127.0.0.1',
                   '--listening-port=' + str(turn_port), '--prometheus', '--prometheus-address=127.0.0.1',
                   '--prometheus-port=' + str(metrics_port), '--relay-threads=2', '--no-tls', '--no-cli',
                   '--allow-loopback-peers', '--log-file=stdout']
        command += ['--prometheus-observe-realm=' + realm for realm in realms]
        command += list(extra)
        if tls:
            command += ['--prometheus-tls', '--prometheus-cert=' + str(ROOT / 'examples/etc/turn_server_cert.pem'),
                        '--prometheus-key=' + str(ROOT / 'examples/etc/turn_server_pkey.pem')]
        environment = dict(os.environ)
        if slow_readers and sys.platform.startswith('linux') and environment.get('TURN_TEST_SLOW_READER_SOURCE'):
            library = directory / 'slow-reader.so'
            subprocess.run([os.environ.get('CC', 'cc'), '-shared', '-fPIC',
                            environment['TURN_TEST_SLOW_READER_SOURCE'], '-ldl', '-o', str(library)], check=True)
            environment['LD_PRELOAD'] = str(library) + (' ' + environment['LD_PRELOAD'] if environment.get('LD_PRELOAD') else '')
            environment['TURN_TEST_METRICS_PORT'] = str(metrics_port)
        with (directory / 'server.log').open('w+') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=environment)
            url = ('https' if tls else 'http') + '://127.0.0.1:' + str(metrics_port) + '/metrics'
            def scrape():
                try:
                    with urllib.request.urlopen(url, timeout=2, context=ssl._create_unverified_context() if tls else None) as response:
                        return response.read().decode()
                except (OSError, TimeoutError):
                    return ''
            try:
                wait_for(lambda: process.poll() is None and scrape(), 'exporter failed to start')
                yield turn_port, metrics_port, scrape, process
            except BaseException:
                log.seek(0)
                # Fixture-only log; never reads a production configuration.
                print(log.read()[-4000:], file=sys.stderr)
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


class Allocation:
    def __init__(self, turn_port, ticket=None):
        self.socket = socket.create_connection(('127.0.0.1', turn_port), timeout=3)
        method = M_REFRESH if ticket else M_ALLOCATE
        extra = [(0x8030,ticket),(A_LIFETIME,struct.pack('!I',600))] if ticket else [(A_REQ_TRANSPORT,UDP_RELAY)]
        self.realm, self.nonce = challenge(self.socket, method, extra)
        assert self.realm and self.nonce
        self.key = hashlib.md5(b'user:' + self.realm + b':pass').digest()

    def request(self, method, extra):
        return make(method, [(A_USERNAME, b'user'), (A_REALM, self.realm), (A_NONCE, self.nonce)] + extra, self.key)

    def allocate(self, extra=()):
        self.message = self.request(M_ALLOCATE, [(A_REQ_TRANSPORT, UDP_RELAY)] + list(extra))
        return parse(xact(self.socket, self.message))

    def close(self):
        self.socket.close()


def check_lifecycle_and_responses():
    with server(extra=('--user-quota=1',)) as (turn_port, _, scrape, _):
        wait_for(lambda: value(samples(scrape()), FAMILIES[-1]) > 0, 'snapshot not ready')
        initial = samples(scrape())
        assert len(initial) == 33, len(initial)
        one = Allocation(turn_port)
        try:
            typ, attrs = one.allocate()
            assert typ == ALLOCATE_OK, errcode(attrs)
            assert parse(xact(one.socket, one.message))[0] == ALLOCATE_OK
            wait_for(lambda: value(samples(scrape()), FAMILIES[2], realm='observed', code='success', cause='none') == 2,
                     'success/retransmit results were not counted once per response')
            current = samples(scrape())
            assert value(current, FAMILIES[3], realm='observed') == 1
            assert value(current, FAMILIES[0], realm='observed') == 1
            assert value(current, FAMILIES[5], realm='observed', activity='new', peer_bytes='zero') == 1
            two = Allocation(turn_port)
            try:
                typ, attrs = two.allocate()
                assert errcode(attrs) == 486
                wait_for(lambda: value(samples(scrape()), FAMILIES[2], realm='observed', code='486', cause='user_quota') == 1,
                         'user quota cause missing')
            finally:
                two.close()
            request = one.request(M_REFRESH, [(A_LIFETIME, struct.pack('!I', 0))])
            assert parse(xact(one.socket, request))[0] == REFRESH_OK
            wait_for(lambda: value(samples(scrape()), FAMILIES[4], realm='observed', reason='client_delete') == 1,
                     'explicit delete not finally closed')
            final = samples(scrape())
            assert value(final, FAMILIES[0], realm='observed') == 0
            assert sum(v for (name, _), v in final.items() if name == FAMILIES[5]) == 0
            assert len(final) == 33
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                snapshots = list(pool.map(lambda _: samples(scrape()), range(12)))
            for item in snapshots:
                assert value(item, FAMILIES[2], realm='observed', code='success', cause='none') == 2
                assert value(item, FAMILIES[3], realm='observed') == 1
        finally:
            one.close()
    print('OK: real Allocate/retransmit/user-quota/delete and concurrent scrape counters')


def check_binding_at_total_quota():
    with server(extra=('--total-quota=1', '--user-quota=0')) as (turn_port, _, scrape, _):
        wait_for(lambda: value(samples(scrape()), FAMILIES[-1]) > 0, 'snapshot not ready')
        one, two = Allocation(turn_port), Allocation(turn_port)
        try:
            assert one.socket.getsockname() != two.socket.getsockname()
            assert one.allocate()[0] == ALLOCATE_OK
            wait_for(lambda: value(samples(scrape()), FAMILIES[0], realm='observed') == 1,
                     'single-family allocation did not consume exactly one quota unit')
            typ, attrs = two.allocate()
            assert typ == 0x0113 and errcode(attrs) == 486, (typ, errcode(attrs))
            wait_for(lambda: value(samples(scrape()), FAMILIES[2], realm='observed', code='486', cause='total_quota') == 1,
                     'authenticated second Allocate did not hit total quota')
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as binding:
                binding.settimeout(3)
                binding.connect(('127.0.0.1', turn_port))
                request = make(0x0001, [])
                binding.send(request)
                response = binding.recv(65536)
                typ, attrs = parse(response)
                assert typ == 0x0101 and response[4:20] == request[4:20]
                mapped = get(attrs, 0x0020)
                assert mapped is not None and len(mapped) == 8 and mapped[:2] == b'\0\x01'
                mapped_port = struct.unpack('!H', mapped[2:4])[0] ^ 0x2112
                mapped_ip = socket.inet_ntoa(bytes(a ^ b for a, b in zip(mapped[4:], request[4:8])))
                assert (mapped_ip, mapped_port) == binding.getsockname()
            current = samples(scrape())
            assert value(current, FAMILIES[0], realm='observed') == 1
            assert value(current, FAMILIES[3], realm='observed') == 1
            assert parse(xact(one.socket, one.request(M_REFRESH, [(A_LIFETIME, struct.pack('!I', 0))])))[0] == REFRESH_OK
            wait_for(lambda: value(samples(scrape()), FAMILIES[0], realm='observed') == 0,
                     'explicit release did not free quota')
            assert two.allocate()[0] == ALLOCATE_OK
            wait_for(lambda: value(samples(scrape()), FAMILIES[0], realm='observed') == 1,
                     'Allocate after release did not reacquire quota')
        finally:
            one.close()
            two.close()
        wait_for(lambda: value(samples(scrape()), FAMILIES[0], realm='observed') == 0,
                 'test allocations retained quota after cleanup')
    print('OK: total-quota=1 rejects authenticated Allocate with 486; UDP Binding preserves transaction/mapped address and quota; release permits Allocate')


def check_final_errors_and_limits():
    with server() as (turn_port, _, scrape, _):
        client = Allocation(turn_port)
        try:
            for i in range(64):
                message = make(M_ALLOCATE, [(A_USERNAME, b'user'), (A_REALM, f'client-{i}'.encode()),
                    (A_NONCE, client.nonce), (A_REQ_TRANSPORT, UDP_RELAY)], client.key)
                _, attrs = parse(xact(client.socket, message))
                assert errcode(attrs) == 437
            _, attrs = client.allocate(((0x7777, b''),))
            assert errcode(attrs) == 420
            wait_for(lambda: value(samples(scrape()), FAMILIES[2], realm='observed', code='437', cause='other') == 64,
                     'mismatched client REALM was not attributed to selected server realm')
            data = samples(scrape())
            assert value(data, FAMILIES[2], realm='observed', code='420', cause='other') == 1
            assert value(data, FAMILIES[3], realm='observed') == 0
            assert len(data) == 33
        finally:
            client.close()
    for extra, cause, expected in ((('--total-quota=1',), 'total_quota', 486),
                                  (('--bps-capacity=1000000', '--max-bps=1000000'), 'bandwidth_quota', 486),
                                  (('--min-port=54991', '--max-port=54991', '--relay-threads=1'), 'capacity', 508)):
        with server(extra=extra) as (turn_port, _, scrape, _):
            one, two = Allocation(turn_port), Allocation(turn_port)
            try:
                assert one.allocate()[0] == ALLOCATE_OK
                _, attrs = two.allocate()
                assert errcode(attrs) == expected, (cause, errcode(attrs))
                wait_for(lambda: value(samples(scrape()), FAMILIES[2], realm='observed', code=str(expected), cause=cause) == 1,
                         'final quota/capacity response missing: ' + cause)
            finally:
                one.close()
                two.close()
            wait_for(lambda: value(samples(scrape()), FAMILIES[0], realm='observed') == 0,
                     'failed relay or transport close retained an unexpected quota count')
            wait_for(lambda:value(samples(scrape()),FAMILIES[4],realm='observed',reason='other')==1,
                     'transport close must close exactly one successfully created allocation')
    print('OK: wire 420/437/486(total,user,bandwidth)/508 and bounded client identifiers')


def check_stateless_udp_results():
    with server(extra=('--stateless-nonce',)) as (turn_port, _, scrape, _):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.connect(('127.0.0.1', turn_port))
            client.settimeout(2)
            def request(attributes, key=None):
                client.send(make(M_ALLOCATE, attributes, key))
                return parse(client.recv(65536))[1]
            attrs = request([(A_REQ_TRANSPORT, UDP_RELAY)])
            assert errcode(attrs) == 401
            nonce = get(attrs, A_NONCE)
            assert errcode(request([(A_REALM, b'observed'), (A_USERNAME, b'user'),
                                    (A_NONCE, b'invalid-nonce')], b'fixture-key')) == 438
            # Integrity's presence selects pre-credential checks; these requests never authenticate.
            for attributes, expected in (([(A_REQ_TRANSPORT, UDP_RELAY)], 400),
                ([(A_REALM, b'observed'), (A_NONCE, nonce)], 400),
                ([(A_REALM, b'untrusted-client-realm'), (A_NONCE, nonce)], 437)):
                assert errcode(request(attributes, b'fixture-key')) == expected
            wait_for(lambda:value(samples(scrape()), FAMILIES[2], realm='observed', code='400', cause='other') == 2,
                     'stateless UDP final 400 responses missing')
            data = samples(scrape())
            assert value(data, FAMILIES[2], realm='observed', code='437', cause='other') == 1
            assert value(data, FAMILIES[3], realm='observed') == 0
            assert sum(v for (name,_),v in data.items() if name == FAMILIES[2]) == 3
            assert len(data) == 33
    with server(extra=('--stateless-nonce', '--unauthorized-ratelimit',
                       '--unauthorized-ratelimit-rps=1')) as (turn_port, _, scrape, _):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.connect(('127.0.0.1', turn_port))
            client.settimeout(0.2)
            for _ in range(16):
                client.send(make(M_ALLOCATE, [(A_REALM, b'untrusted-client-realm')], b'fixture-key'))
            replies = 0
            while True:
                try:
                    assert errcode(parse(client.recv(65536))[1]) == 437
                    replies += 1
                except socket.timeout:
                    break
            assert 0 < replies < 16, replies
            wait_for(lambda:value(samples(scrape()), FAMILIES[2], realm='observed', code='437', cause='other') == replies,
                     'rate-limited stateless replies counted without a final body')
    print('OK: stateless UDP 400/437 selected-realm results; 401/438 and rate-limited drops excluded')


def check_expiry_refresh_and_partial_family():
    for action in ('expiry', 'cancel-delete', 'failed-refresh'):
        with server(extra=('--max-allocate-lifetime=2',)) as (turn_port, _, scrape, _):
            client = Allocation(turn_port)
            try:
                assert client.allocate()[0] == ALLOCATE_OK
                if action != 'expiry':
                    assert parse(xact(client.socket, client.request(M_REFRESH, [(A_LIFETIME, struct.pack('!I', 0))])))[0] == REFRESH_OK
                if action == 'failed-refresh':
                    wrong = make(M_REFRESH, [(A_USERNAME,b'user'), (A_REALM,b'wrong'), (A_NONCE,client.nonce),
                        (A_LIFETIME,struct.pack('!I',10))],client.key)
                    assert errcode(parse(xact(client.socket,wrong))[1]) == 441
                    reason = 'client_delete'
                else:
                    typ, attrs = parse(xact(client.socket, client.request(M_REFRESH, [(A_LIFETIME, struct.pack('!I', 600))])))
                    assert typ == REFRESH_OK
                    granted = struct.unpack('!I', get(attrs,A_LIFETIME))[0]
                    assert granted == 2, granted
                    print(f'OK: {action} wire REFRESH granted lifetime={granted}', flush=True)
                    reason = 'expired'
                wait_for(lambda: value(samples(scrape()), FAMILIES[4], realm='observed', reason=reason) == 1,
                         'final lifetime close reason was not ' + reason)
                data = samples(scrape())
                assert sum(v for (name,_),v in data.items() if name == FAMILIES[4]) == 1
            finally:
                client.close()
    with server(extra=('--relay-ip=::1','--max-allocate-lifetime=2')) as (turn_port, _, scrape, _):
        client = Allocation(turn_port)
        try:
            typ, attrs = client.allocate(((0x8000,b'\x02\0\0\0'),))
            assert typ == ALLOCATE_OK, errcode(attrs)
            assert len([entry for entry in attrs if entry[0] == 0x0016]) == 2, 'dual family allocation unavailable'
            for family,lifetime in ((1,0),(2,600)):
                response = client.request(M_REFRESH, [(0x0017,bytes((family,0,0,0))),
                    (A_LIFETIME,struct.pack('!I',lifetime))])
                assert parse(xact(client.socket,response))[0] == REFRESH_OK
            wait_for(lambda: value(samples(scrape()), FAMILIES[4], realm='observed', reason='expired') == 1,
                     'last surviving family must determine final expiry reason')
            data=samples(scrape())
            assert value(data,FAMILIES[3],realm='observed') == 1
            assert value(data,FAMILIES[4],realm='observed',reason='client_delete') == 0
        finally:
            client.close()
    print('OK: expiry, delete cancellation, failed REFRESH and partial dual-stack final reason')


def xor_address(address, port):
    return b'\0\x01' + struct.pack('!H',port ^ 0x2112) + bytes(a ^ b for a,b in zip(socket.inet_aton(address),b'\x21\x12\xa4\x42'))


def check_accepted_data_and_framing():
    with server() as (turn_port, _, scrape, _):
        client=Allocation(turn_port)
        peer=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        peer.bind(('127.0.0.1',0))
        peer.settimeout(3)
        try:
            typ,attrs=client.allocate()
            assert typ==ALLOCATE_OK
            relayed=get(attrs,0x0016)
            relay=('127.0.0.1',struct.unpack('!H',relayed[2:4])[0] ^ 0x2112)
            before = value(samples(scrape()),FAMILIES[-1])
            peer.sendto(b'forbidden',relay)
            wait_for(lambda:value(samples(scrape()),FAMILIES[-1]) >= before+2, 'forbidden packet observation did not converge')
            wait_for(lambda:value(samples(scrape()),FAMILIES[5],realm='observed',activity='new',peer_bytes='zero')==1,
                     'unpermitted peer traffic activated the allocation')
            destination=xor_address('127.0.0.1',peer.getsockname()[1])
            assert parse(xact(client.socket,client.request(8,[(0x0012,destination)])))[0]==0x0108
            # Stay below coturn's existing UDP receive-buffer capacity.
            payload=b'x'*8192
            for _ in range(4):
                client.socket.sendall(make(0x0016,[(0x0012,destination),(0x0013,payload)]))
                assert peer.recvfrom(65536)[0]==payload
                peer.sendto(payload,relay)
                received=get(parse(recv_stun(client.socket))[1],0x0013)
                assert received==payload, ('peer payload length', len(received) if received is not None else None)
            wait_for(lambda:value(samples(scrape()),FAMILIES[5],realm='observed',activity='new',peer_bytes='le_64k')==1,
                     'UDP SEND and peer payload did not total exactly65536')
            assert parse(xact(client.socket,client.request(9,[(0x000c,b'\x40\0\0\0'),(0x0012,destination)])))[0]==0x0109
            client.socket.sendall(struct.pack('!HH',0x4000,1)+b'z'+b'\0'*3)
            assert peer.recvfrom(65536)[0]==b'z'
            wait_for(lambda:value(samples(scrape()),FAMILIES[5],realm='observed',activity='new',peer_bytes='gt_64k')==1,
                     'ChannelData payload did not cross65536 without counting framing')
        finally:
            peer.close()
            client.close()
    print('OK: permission gate, UDP SEND/peer payload, 65536/65537 and ChannelData framing')


def check_mobility_preserves_one_lifecycle():
    with server(extra=('--mobility','--total-quota=1','--user-quota=1','--max-allocate-timeout=5')) as (turn_port,_,scrape,process):
        original=Allocation(turn_port)
        typ,attrs=original.allocate(((0x8030,b''),))
        assert typ==ALLOCATE_OK
        ticket=get(attrs,0x8030)
        assert ticket
        original.close()
        resumed=Allocation(turn_port,ticket)
        try:
            reply=resumed.request(M_REFRESH,[(0x8030,ticket),(A_LIFETIME,struct.pack('!I',600))])
            typ,attrs=parse(xact(resumed.socket,reply))
            assert typ==REFRESH_OK, errcode(attrs)
            # The real handoff is triggered by the first Send indication on the new path.
            resumed.socket.sendall(make(0x0016,[(0x0012,xor_address('127.0.0.1',59999)),(0x0013,b'x')]))
            database=Path(next(arg[5:] for arg in process.args if arg.startswith('--db=')))
            wait_for(lambda:'mobility handoff completed' in (database.parent/'server.log').read_text(),
                     'actual mobility handoff did not execute')
            wait_for(lambda:value(samples(scrape()),FAMILIES[3],realm='observed')==1,'mobility created count missing')
            data=samples(scrape())
            assert value(data,FAMILIES[0],realm='observed')==1
            assert sum(v for (name,_),v in data.items() if name==FAMILIES[4])==0
            assert sum(v for (name,_),v in data.items() if name==FAMILIES[5])==1
            reply=resumed.request(M_REFRESH,[(A_LIFETIME,struct.pack('!I',0))])
            assert parse(xact(resumed.socket,reply))[0]==REFRESH_OK
            # Mobility's first-stage timeout preserves the logical allocation; its existing watchdog finalizes it.
            wait_for(lambda:value(samples(scrape()),FAMILIES[4],realm='observed',reason='client_delete')==1,
                     'resumed allocation watchdog did not close exactly once')
            assert value(samples(scrape()),FAMILIES[3],realm='observed')==1
        finally:
            resumed.close()
    print('OK: mobility suspension/resume/handoff preserves one allocation and quota unit')


def check_freshness_between_scrapes():
    with server() as (_, _, scrape, _):
        wait_for(lambda:value(samples(scrape()),FAMILIES[-1]) > 0, 'snapshot not ready')
        sample_time = producer_time = 0
        receipt = []
        evidence = Path(os.environ['TURN_TEST_EVIDENCE_DIR']) if os.environ.get('TURN_TEST_EVIDENCE_DIR') else None
        if evidence:
            evidence.mkdir(parents=True, exist_ok=True)
        start=time.monotonic()
        for second in range(46):
            if second % 15 == 0:
                body = scrape()
                producer_time=value(samples(body),FAMILIES[-1])
                sample_time=time.time()
                if evidence:
                    (evidence / f'scrape-{second:02d}.prom').write_text(body)
            receipt.append({'second': second, 'evaluationTime': time.time(), 'sampleTime': sample_time,
                            'producerTime': producer_time})
            assert producer_time > 0 and abs(sample_time-producer_time) <= 5
            assert 0 <= time.time()-sample_time <= 30
            if second < 45:
                time.sleep(max(0,start+second+1-time.monotonic()))
        if evidence:
            (evidence / 'samples.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('OK: actual endpoint scrape15s/eval1s for45s stays fresh between scrapes')


def check_cardinality_and_unknown():
    with server(realms=('missing',), extra=('--total-quota=9', '--user-quota=4')) as (_, _, scrape, _):
        data = wait_for(lambda: (current if value(current := samples(scrape()), FAMILIES[-1]) > 0 else None),
                        'unreferenced realm kept the snapshot unready')
        assert len(data) == 33
        assert value(data, FAMILIES[0], realm='missing') == 0
        assert value(data, FAMILIES[1], realm='missing', scope='total') == 9
        assert value(data, FAMILIES[1], realm='missing', scope='user') == 4
    # The existing DB origin map creates these actual server realms, not the observer.
    realms = tuple((str(i) + '"\\' * 381)[:763] for i in range(16))
    for tls in (False, True):
        with server(realms=realms, known_realms=realms, default=realms[0], slow_readers=True, tls=tls) as (_, metrics_port, scrape, process):
            data = wait_for(lambda: (current if len(current := samples(scrape())) == 513 else None),
                            '16 configured realms were not represented by exactly 513 series')
            assert value(data, FAMILIES[-1]) > 0
            assert {dict(labels)['realm'] for (name, labels) in data if name == FAMILIES[0]} == set(realms)
            assert len(scrape().encode()) < 1024*1024
            if not os.environ.get('TURN_TEST_SLOW_READER_SOURCE'):
                continue
            # Each connection has a real response in flight; MHD admission precedes formatting.
            readers = []
            try:
                for _ in range(8):
                    sock = socket.socket()
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
                    sock.settimeout(3)
                    sock.connect(('127.0.0.1', metrics_port))
                    if tls:
                        sock = ssl._create_unverified_context().wrap_socket(sock, server_hostname='localhost')
                    sock.sendall(b'GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                    assert sock.recv(1) == b'H'
                    readers.append(sock)
                if sys.platform.startswith('linux'):
                    owned = {str(fd.readlink()) for fd in Path('/proc', str(process.pid), 'fd').iterdir() if fd.is_symlink()}
                    active = [line.split()[4] for line in Path('/proc/net/tcp').read_text().splitlines()[1:]
                              if line.split()[1].split(':')[1] == f'{metrics_port:04X}' and line.split()[3] == '01'
                              and f'socket:[{line.split()[9]}]' in owned]
                    assert len(active) == 8, f'expected 8 retained server responses, got {len(active)}'
                    assert all(int(queue.split(':')[0], 16) for queue in active), active
                    print('OK: eight accepted server sockets have pending response bytes', active)
                ninth = socket.create_connection(('127.0.0.1', metrics_port), timeout=2)
                try:
                    denied = False
                    if tls:
                        try:
                            ninth = ssl._create_unverified_context().wrap_socket(ninth, server_hostname='localhost')
                        except (TimeoutError, ConnectionResetError, ssl.SSLError):
                            denied = True
                    if not denied:
                        ninth.sendall(b'GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n')
                        try:
                            assert not ninth.recv(1), 'ninth response bypassed the connection limit'
                        except (TimeoutError, ConnectionResetError):
                            pass
                finally:
                    ninth.close()
            finally:
                for reader in readers:
                    reader.close()
            wait_for(scrape, 'exporter did not recover after readers disconnected')
    print('OK: unreferenced realm reports default limits; HTTP and TLS have 513 series at maximum escaped realm length')
    if os.environ.get('TURN_TEST_SLOW_READER_SOURCE'):
        print('OK: instrumented HTTP/TLS eight-reader admission; exporter recovered after disconnect')


if __name__ == '__main__':
    check_lifecycle_and_responses()
    check_binding_at_total_quota()
    check_final_errors_and_limits()
    check_stateless_udp_results()
    check_expiry_refresh_and_partial_family()
    check_accepted_data_and_framing()
    check_mobility_preserves_one_lifecycle()
    check_freshness_between_scrapes()
    check_cardinality_and_unknown()
