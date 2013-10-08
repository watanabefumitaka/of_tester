# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import base64
import json
import logging
import os
import struct
import sys
import traceback

from ryu import log
from ryu.base import app_manager
from ryu.controller import controller
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.exception import RyuException
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser


""" Required test network.

                      +---------+
           +----------| test sw | The switch to test
           |          +---------+
    +------------+      (1) (2)
    | controller |       |   |
    +------------+      (1) (2)
           |          +---------+
           +----------| sub sw  | Open vSwtich
                      +---------+

      (X) : port number

    Tests send a packet from port 1 of the Open vSwitch. If the packet
    matched with a flow entry of the switch to test, the switch resends
    the packet from port 2, according to the flow entry. then the Open
    vSwitch receives the packet and sends a PacketIn message. if the
    packet did not match, the switch to test sends a PacketIn message.

    In other words, when a test succeeded, the controller will receive
    a PacketIn message from the Open vSwitch, otherwise it will receive
    from the switch to test.

"""


DEFAULT_DIRECTORY = './'

TEST_SW_ID = dpid_lib.str_to_dpid('0000000000000001')
SUB_SW_ID = dpid_lib.str_to_dpid('0000000000000002')
SUB_SW_SENDER_PORT = 1

WAIT_TIMER = 5  # sec

# Test state.
STATE_INIT = 0
STATE_FLOW_INSTALL = 1
STATE_FLOW_EXIST_CHK = 2
STATE_FLOW_MATCH_CHK = 3
STATE_GET_MATCH_COUNT = 4
STATE_UNMATCH_PKT_SEND = 5
STATE_FLOW_UNMATCH_CHK = 6
STATE_NG_FLOW_INSTALL = 7

# Test result.
OK = 'OK'
NG = 'NG (%(detail)s)'
RYU_INTERNAL_ERROR = '- (Ryu internal error.)'
TEST_FILE_ERROR = '%(file)s : Test file format error (%(detail)s)'
NO_TEST_FILE = 'Test file (*.json) is not found.'
INVALID_PATH = '%(path)s : No such file or directory.'

# Test result details.
FAILURE = 0
TIMEOUT = 1
RCV_ERR = 2

MSG = {STATE_FLOW_INSTALL:
       {TIMEOUT: 'flows install is failure. no OFPBarrierReply.',
        RCV_ERR: 'flows install is failure. %(err_msg)s'},
       STATE_FLOW_EXIST_CHK:
       {FAILURE: 'expected flow was not installed.',
        RCV_ERR: 'flow existence check is failure. %(err_msg)s'},
       STATE_FLOW_MATCH_CHK:
       {TIMEOUT: 'flow matching is failure. no expected OFPPacketIn.',
        RCV_ERR: 'flow matching is failure. sub SW error. %(err_msg)s'},
       STATE_GET_MATCH_COUNT:
       {TIMEOUT: 'flow unmatching check is failure. no OFPFlowStatsReply.',
        RCV_ERR: 'flow unmatching check is failure. %(err_msg)s'},
       STATE_UNMATCH_PKT_SEND:
       {TIMEOUT: 'flow unmatching check is failure. no OFPBarrierReply.',
        RCV_ERR: 'flow unmatching check is failure. %(err_msg)s'},
       STATE_FLOW_UNMATCH_CHK:
       {FAILURE: 'send packet was matched with the flow.',
        TIMEOUT: 'flow unmatching check is failure. no OFPFlowStatsReply.',
        RCV_ERR: 'flow unmatching check is failure. %(err_msg)s'},
       STATE_NG_FLOW_INSTALL:
       {FAILURE: 'invalid flows install is failure. no expected OFPErrorMsg.',
        TIMEOUT: 'invalid flows install is failure. no OFPBarrierReply.'}}

ERR_MSG = 'OFPErrorMsg received. type=0x%02x code=0x%02x data=%s'


GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[33m'
END_TAG = '\033[0m'


def coloring(msg, color):
    return color + msg + END_TAG


class TestFailure(RyuException):
    def __init__(self, state):
        msg = NG % {'detail': MSG[state][FAILURE]}
        super(TestFailure, self).__init__(msg)


class TestTimeout(RyuException):
    def __init__(self, state):
        msg = NG % {'detail': MSG[state][TIMEOUT]}
        super(TestTimeout, self).__init__(msg)


class TestReceiveError(RyuException):
    def __init__(self, state, err_msg):
        msg = NG % {'detail': MSG[state][RCV_ERR] % {'err_msg': ERR_MSG % (
            err_msg.type, err_msg.code, repr(err_msg.data))}}
        super(TestReceiveError, self).__init__(msg)


class TestEnvironmentError(RyuException):
    message = 'dpid=%(dpid)s : At least three links are required.'


def main():
    """ main function. start OpenFlowSwitch Tester. """
    log.init_log()

    app_lists = ['of_tester',
                 'ryu.controller.ofp_handler']
    app_mgr = app_manager.AppManager()
    app_mgr.load_apps(app_lists)
    contexts = app_mgr.create_contexts()
    app_mgr.instantiate_apps(**contexts)

    ctlr = controller.OpenFlowController()
    thr = hub.spawn(ctlr)

    try:
        hub.joinall([thr])
    finally:
        app_mgr.close()


if __name__ == "__main__":
    main()


class OfTester(app_manager.RyuApp):
    """ OpenFlowSwitch Tester. """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self):
        super(OfTester, self).__init__()
        self._set_logger()
        self.test_sw = None
        self.sub_sw = None
        self.state = STATE_INIT
        self.test_thread = None
        self.waiter = None
        self.send_msg_xids = []
        self.rcv_msgs = []
        self.test_files = (sys.argv[1:] if len(sys.argv) > 1
                           else [DEFAULT_DIRECTORY])
        self.logger.info('Test files or directory = %s', self.test_files)

    def _set_logger(self):
        self.logger.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[%(levelname)s] %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        self.logger.addHandler(hdlr)

    def close(self):
        self._test_terminate()

    def _test_terminate(self):
        if self.test_thread is not None:
            hub.kill(self.test_thread)
            hub.joinall([self.test_thread])
            self.test_thread = None
            self.logger.info('--- Test terminated ---')

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [handler.MAIN_DISPATCHER, handler.DEAD_DISPATCHER])
    def dispacher_change(self, ev):
        assert ev.datapath is not None
        if ev.state == handler.MAIN_DISPATCHER:
            self._register_sw(ev.datapath)
        elif ev.state == handler.DEAD_DISPATCHER:
            self._unregister_sw(ev.datapath)

    def _register_sw(self, dp):
        try:
            if dp.id == TEST_SW_ID:
                self.test_sw = TestSw(dp, self.logger)
                self.logger.info('dpid=%s : Join test SW.',
                                 dpid_lib.dpid_to_str(dp.id))
            elif dp.id == SUB_SW_ID:
                self.sub_sw = SubSw(dp, self.logger)
                self.logger.info('dpid=%s : Join sub SW.',
                                 dpid_lib.dpid_to_str(dp.id))
        except TestEnvironmentError as err:
            self.logger.error(str(err))
            return

        if self.test_sw and self.sub_sw:
            self.test_thread = hub.spawn(self._test_execute)

    def _unregister_sw(self, dp):
        if dp.id == TEST_SW_ID or dp.id == SUB_SW_ID:
            self._test_terminate()

            if dp.id == TEST_SW_ID:
                del self.test_sw
                self.test_sw = None
                self.logger.info('dpid=%s : Leave test SW.',
                                 dpid_lib.dpid_to_str(dp.id))
            else:  # dp.id == SUB_SW_ID
                del self.sub_sw
                self.sub_sw = None
                self.logger.info('dpid=%s : Leave sub SW.',
                                 dpid_lib.dpid_to_str(dp.id))

    def _test_execute(self):
        """ Execute OpenFlowSwitch test. """
        # Parse test pattern from test files.
        tests = TestPatterns(self.test_files, self.logger)
        if not tests:
            msg = coloring(NO_TEST_FILE, YELLOW)
            self.logger.warning(msg)
            return

        self.logger.info('--- Test start ---')
        for test in tests:
            # Test execute.
            try:
                if not test.error:
                    # 1. Install flows.
                    for flow in test.flows:
                        self._test(STATE_FLOW_INSTALL, flow)
                        self._test(STATE_FLOW_EXIST_CHK, flow)
                    # 2. Check flow matching.
                    for pkt in test.packets:
                        if 'output' in pkt or 'PACKET_IN' in pkt:
                            self._test(STATE_FLOW_MATCH_CHK, pkt)
                        else:
                            before_stats = self._test(STATE_GET_MATCH_COUNT)
                            self._test(STATE_UNMATCH_PKT_SEND, pkt)
                            self._test(STATE_FLOW_UNMATCH_CHK, before_stats)
                else:
                    # 1. Install invalid flows.
                    self._test(STATE_NG_FLOW_INSTALL, test.flows, test.error)

                result = OK
            except (TestFailure, TestTimeout, TestReceiveError) as err:
                result = str(err)
                if test.description:
                    result += os.linesep + unicode(test.description)
            except Exception:
                result = RYU_INTERNAL_ERROR

            # Output test result.
            msg = (coloring(result, GREEN) if result == OK
                   else coloring(result, RED))
            self.logger.info('%s : %s', test.name, msg)
            if result == RYU_INTERNAL_ERROR:
                self.logger.error(traceback.format_exc())

            #TODO: for debug
            #print raw_input("> Enter")

            # Initialize for next test.
            self.test_sw.del_test_flow()
            self.state = STATE_INIT

        self.test_thread = None
        self.logger.info('---  Test end  ---')

    def _test(self, state, *args):
        test = {STATE_FLOW_INSTALL: self._test_flow_install,
                STATE_FLOW_EXIST_CHK: self._test_flow_exist_check,
                STATE_FLOW_MATCH_CHK: self._test_flow_matching_check,
                STATE_GET_MATCH_COUNT: self._test_get_match_count,
                STATE_UNMATCH_PKT_SEND: self._test_unmatch_packet_send,
                STATE_FLOW_UNMATCH_CHK: self._test_flow_unmatching_check,
                STATE_NG_FLOW_INSTALL: self._test_invalid_flow_install}

        self.send_msg_xids = []
        self.rcv_msgs = []

        self.state = state
        return test[state](*args)

    def _test_flow_install(self, flow):
        xid = self.test_sw.add_flow(flow_mod=flow)
        self.send_msg_xids.append(xid)

        xid = self.test_sw.send_barrier_request()
        self.send_msg_xids.append(xid)

        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, ofproto_v1_3_parser.OFPBarrierReply)

    def _test_flow_exist_check(self, flow_mod):
        xid = self.test_sw.send_flow_stats()
        self.send_msg_xids.append(xid)
        self._wait()
        for msg in self.rcv_msgs:
            assert isinstance(msg, ofproto_v1_3_parser.OFPFlowStatsReply)
            for stats in msg.body:
                if self._compare_flow(stats, flow_mod):
                    return
        raise TestFailure(self.state)

    def _test_flow_matching_check(self, pkt):
        self.logger.debug("send_packet:[%s]", packet.Packet(pkt['input']))
        self.logger.debug("output:[%s]", packet.Packet(pkt.get('output')))
        self.logger.debug("packet_in:[%s]",
                          packet.Packet(pkt.get('packet_in')))

        # 1. send a packet from the Open vSwitch.
        self.sub_sw.send_packet_out(pkt['input'])

        # 2. receive a PacketIn message.
        rcv_pkt_model = (pkt['output'] if 'output' in pkt
                         else pkt['packet_in'])
        pkt_in_src_model = (self.sub_sw if 'output' in pkt
                            else self.test_sw)

        timer = hub.Timeout(WAIT_TIMER)
        timeout = False
        try:
            while True:
                self._wait(timer=False)

                assert len(self.rcv_msgs) == 1
                msg = self.rcv_msgs[0]
                assert isinstance(msg, ofproto_v1_3_parser.OFPPacketIn)

                # 3. confirm which switch sent the message.
                if msg.datapath.id != pkt_in_src_model.dp.id:
                    self.logger.debug("received PacketIn from unsuitable SW.")
                    continue
                self.logger.debug("receive_packet:[%s]",
                                  packet.Packet(msg.data))
                if str(msg.data) != str(rcv_pkt_model):
                    self.logger.debug("receive_packet is unmatch.")
                    continue
                break

        except hub.Timeout as t:
            if t is not timer:
                raise RyuException('Internal error. Not my timeout.')
            timeout = True
        finally:
            timer.cancel()
            if self.waiter is not None:
                self.waiter.set()
                self.waiter = None

        if timeout:
            raise TestTimeout(self.state)

    def _test_get_match_count(self):
        xid = self.test_sw.send_flow_stats()
        self.send_msg_xids.append(xid)
        self._wait()
        return [stats for msg in self.rcv_msgs for stats in msg.body]

    def _test_unmatch_packet_send(self, pkt):
        # send a packet from the Open vSwitch.
        self.logger.debug("send_packet:[%s]", packet.Packet(pkt['input']))
        self.sub_sw.send_packet_out(pkt['input'])

        # wait OFPBarrierReply.
        xid = self.sub_sw.send_barrier_request()
        self.send_msg_xids.append(xid)
        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, ofproto_v1_3_parser.OFPBarrierReply)

    def _test_flow_unmatching_check(self, before_stats):
        # check match packet count
        xid = self.test_sw.send_flow_stats()
        self.send_msg_xids.append(xid)
        self._wait()
        for msg in self.rcv_msgs:
            assert isinstance(msg, ofproto_v1_3_parser.OFPFlowStatsReply)
            for stats in msg.body:
                for before_stat in before_stats:
                    if self._compare_flow(stats, before_stat):
                        if stats.packet_count != before_stat.packet_count:
                            raise TestFailure(self.state)
                        before_stats.remove(before_stat)
                        break
                if before_stats:
                    raise RyuException('Internal error. Unknown flow was'
                                       ' installed. %s', before_stats)

    def _test_invalid_flow_install(self, flows, error):
        def __compare_error(msg, pattern):
            compare_list = [[msg.version, pattern.version],
                            [msg.msg_type, pattern.msg_type],
                            [msg.type, pattern.type],
                            [msg.code, pattern.code]]
            for value in compare_list:
                if value[0] != value[1]:
                    return False
            head_len = struct.calcsize('!BBHI')
            msg_data = msg.data[head_len:]
            msg_len = len(msg_data)
            error_data = error.data[head_len:head_len + msg_len]
            if msg_data != error_data:
                return False
            return True

        # Install test flow.
        for flow in flows:
            xid = self.test_sw.add_flow(flow_mod=flow)
            self.send_msg_xids.append(xid)
        if not self.rcv_msgs:
            xid = self.test_sw.send_barrier_request()
            self.send_msg_xids.append(xid)
            self._wait()

        # Compare error message.
        for err_msg in self.rcv_msgs:
            if not isinstance(err_msg, ofproto_v1_3_parser.OFPErrorMsg):
                continue
            if __compare_error(err_msg, error):
                return
        raise TestFailure(self.state)

    def _compare_flow(self, stats1, stats2):
        attr_list = ['cookie', 'priority', 'flags', 'hard_timeout',
                     'idle_timeout', 'table_id', 'instructions', 'match']
        for attr in attr_list:
            value1 = getattr(stats1, attr)
            value2 = getattr(stats2, attr)
            if str(value1) != str(value2):
                return False
        return True

    def _wait(self, timer=True):
        """ Wait until specific OFP message received
             or timer is exceeded. """
        assert self.waiter is None

        self.waiter = hub.Event()
        if self.state != STATE_NG_FLOW_INSTALL:
            self.rcv_msgs = []
        timeout = False

        if timer:
            timer = hub.Timeout(WAIT_TIMER)
            try:
                self.waiter.wait()
            except hub.Timeout as t:
                if t is not timer:
                    raise RyuException('Internal error. Not my timeout.')
                timeout = True
            finally:
                timer.cancel()
        else:
            self.waiter.wait()

        self.waiter = None

        if timeout:
            raise TestTimeout(self.state)
        if (self.state != STATE_NG_FLOW_INSTALL and
                self.rcv_msgs and isinstance(
                    self.rcv_msgs[0], ofproto_v1_3_parser.OFPErrorMsg)):
            raise TestReceiveError(self.state, self.rcv_msgs[0])

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, handler.MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        if ((self.state == STATE_FLOW_EXIST_CHK
                or self.state == STATE_GET_MATCH_COUNT
                or self.state == STATE_FLOW_UNMATCH_CHK)
                and self.waiter is not None
                and ev.msg.xid in self.send_msg_xids):
            self.rcv_msgs.append(ev.msg)
            if not ev.msg.flags & ev.msg.datapath.ofproto.OFPMPF_REPLY_MORE:
                self.waiter.set()
                hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, handler.MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        if ((self.state == STATE_FLOW_INSTALL
                or self.state == STATE_NG_FLOW_INSTALL
                or self.state == STATE_UNMATCH_PKT_SEND)
                and self.waiter is not None
                and ev.msg.xid in self.send_msg_xids):
            self.rcv_msgs.append(ev.msg)
            self.waiter.set()
            hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if self.state == STATE_FLOW_MATCH_CHK and self.waiter is not None:
            self.rcv_msgs.append(ev.msg)
            self.waiter.set()
            hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [handler.HANDSHAKE_DISPATCHER,
                                             handler.CONFIG_DISPATCHER,
                                             handler.MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        print self.send_msg_xids
        print ev.msg.xid
        if self.state != STATE_INIT and ev.msg.xid in self.send_msg_xids:
            self.rcv_msgs.append(ev.msg)
            if self.waiter is not None:
                self.waiter.set()
                hub.sleep(0)


class OpenFlowSw(object):
    def __init__(self, dp, logger):
        super(OpenFlowSw, self).__init__()
        self.dp = dp
        self.logger = logger
        if len(dp.ports) < 3:
            raise TestEnvironmentError(dpid=dpid_lib.dpid_to_str(dp.id))

    def _send_msg(self, msg):
        msg.xid = None
        self.dp.set_xid(msg)
        self.dp.send_msg(msg)
        return msg.xid

    def add_flow(self, flow_mod=None, out_port=None):
        """ Add flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser

        if flow_mod:
            mod = flow_mod
        else:
            match = parser.OFPMatch()
            max_len = (0 if out_port != ofp.OFPP_CONTROLLER
                       else ofp.OFPCML_MAX)
            actions = [parser.OFPActionOutput(out_port, max_len)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            mod = parser.OFPFlowMod(self.dp, cookie=0,
                                    command=ofp.OFPFC_ADD,
                                    match=match, instructions=inst)
        return self._send_msg(mod)

    def send_barrier_request(self):
        """ send a BARRIER_REQUEST message."""
        parser = self.dp.ofproto_parser
        req = parser.OFPBarrierRequest(self.dp)
        return self._send_msg(req)


class TestSw(OpenFlowSw):
    def __init__(self, dp, logger):
        super(TestSw, self).__init__(dp, logger)

    def del_test_flow(self):
        """ Delete all flow except default flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        mod = parser.OFPFlowMod(self.dp,
                                table_id=ofp.OFPTT_ALL,
                                command=ofp.OFPFC_DELETE,
                                out_port=ofp.OFPP_ANY,
                                out_group=ofp.OFPG_ANY)
        self.dp.send_msg(mod)

    def send_flow_stats(self):
        """ Get all flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(self.dp, 0, ofp.OFPTT_ALL,
                                         ofp.OFPP_ANY, ofp.OFPG_ANY,
                                         0, 0, parser.OFPMatch())
        return self._send_msg(req)


class SubSw(OpenFlowSw):
    def __init__(self, dp, logger):
        super(SubSw, self).__init__(dp, logger)
        # Add packet in flow.
        ofp = self.dp.ofproto
        self.add_flow(out_port=ofp.OFPP_CONTROLLER)

    def send_packet_out(self, data):
        """ send a PacketOut message."""
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        actions = [parser.OFPActionOutput(SUB_SW_SENDER_PORT)]
        out = parser.OFPPacketOut(
            datapath=self.dp, buffer_id=ofp.OFP_NO_BUFFER,
            data=data, in_port=ofp.OFPP_CONTROLLER, actions=actions)
        self.dp.send_msg(out)


class TestPatterns(list):
    """ List of Test class objects. """
    def __init__(self, test_files, logger):
        super(TestPatterns, self).__init__()
        self.logger = logger

        # Parse test pattern from test files.
        for path in test_files:
            self._get_tests(path)

    def _get_tests(self, path):
        if not os.path.exists(path):
            msg = coloring(INVALID_PATH % {'path': path}, YELLOW)
            self.logger.warning(msg)
            return

        if os.path.isdir(path):  # Directory
            for test_path in os.listdir(path):
                test_path = path + (test_path if path[-1:] == '/'
                                    else '/%s' % test_path)
                self._get_tests(test_path)

        elif os.path.isfile(path):  # File
            (dummy, ext) = os.path.splitext(path)
            if ext == '.json':
                buf = open(path, 'rb').read()
                try:
                    json_list = json.loads(buf)
                    for i, test_json in enumerate(json_list):
                        if len(json_list) == 1:
                            i = None
                        self.append(Test(path, i, test_json))
                except (ValueError, TypeError) as e:
                    result = (TEST_FILE_ERROR %
                              {'file': path, 'detail': e.message})
                    msg = coloring(result, YELLOW)
                    self.logger.warning(msg)


class Test(object):
    def __init__(self, test_file_path, number, test_json):
        super(Test, self).__init__()
        self.name = test_file_path.rstrip('.json')
        if number is not None:
            self.name += '_%d' % number
        (self.description,
         self.flows,
         self.error,
         self.packets) = self._parse_test(test_json)

    def _parse_test(self, buf):
        def __ofp_from_json(key, buf, field):
            if key in buf:
                cls = getattr(ofproto_v1_3_parser, key)
                msg = cls.from_jsondict(buf[key], datapath=DummyDatapath())
                msg.version = ofproto_v1_3.OFP_VERSION
                msg.msg_type = msg.cls_msg_type
                msg.xid = 0
                return msg
            else:
                raise ValueError('"%s" field requires "%s."' % (field, key))

        description = buf.get('description')

        # parse 'FLOW_MOD'
        flows = []
        if not 'FLOW_MOD' in buf:
            raise ValueError('a test requires a "FLOW_MOD" block')
        for flow in buf['FLOW_MOD']:
            msg = __ofp_from_json('OFPFlowMod', flow, 'FLOW_MOD')
            flows.append(msg)

        # parse 'ERROR'
        error = None
        if 'ERROR' in buf:
            error = __ofp_from_json('OFPErrorMsg', buf['ERROR'], 'ERROR')

        # parse 'packets'
        packets = []
        if not 'packets' in buf:
            if not error:
                raise ValueError('a test requires "packet" block '
                                 'when an "ERROR" block does not exist.')
        elif not error:
            for pkt in buf['packets']:
                pkt_data = {}
                # parse 'input'
                if not 'input' in pkt:
                    raise ValueError('a test requires "input" field '
                                     'when an "ERROR" block does not exist.')
                pkt_data['input'] = base64.b64decode(pkt['input'])

                # parse 'output'
                out_pkt = None
                if 'output' in pkt:
                    pkt_data['output'] = base64.b64decode(pkt['output'])

                # parse 'PACKET_IN'
                pkt_in_pkt = None
                if 'PACKET_IN' in pkt:
                    pkt_data['PACKET_IN'] = base64.b64decode(pkt['PACKET_IN'])

                if out_pkt and pkt_in_pkt:
                    raise ValueError(
                        'There must not be both "output" and "PACKET_IN"'
                        ' field when an "ERROR" block does not exist.')
                packets.append(pkt_data)

        return (description, flows, error, packets)


class DummyDatapath(object):
    def __init__(self):
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser
