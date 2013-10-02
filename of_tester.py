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
STATE_NG_FLOW_INSTALL = 4

# Test result.
OK = 'OK'
NG = 'NG (%(detail)s)'
RYU_INTERNAL_ERROR = '- (Ryu internal error.)'
TEST_FILE_ERROR = '%(file)s : Test file format error (%(detail)s)'
NO_TEST_FILE = 'Test file (*.json) is not found.'
INVALID_PATH = '%(path)s : No such file or directory.'

OK_GREEN = '\033[92m'
NG_RED = '\033[91m'
ENDC = '\033[0m'

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
       STATE_NG_FLOW_INSTALL:
       {FAILURE: 'invalid flows install is failure. no expected OFPErrorMsg.',
        TIMEOUT: 'invalid flows install is failure. no OFPBarrierReply.'}}

ERR_MSG = 'OFPErrorMsg received. type=0x%02x code=0x%02x data=%s'


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
            self.logger.warning(NO_TEST_FILE)
            return

        self.logger.info('--- Test start ---')
        for test in tests:
            #self.logger.info("%s : [%s]", test.name, test.description)
            # Test execute.
            try:
                if not test.error:
                    # 1. Install flows.
                    for flow in test.flows:
                        self._test(STATE_FLOW_INSTALL, flow)
                        self._test(STATE_FLOW_EXIST_CHK, flow)
                    # 2. Check flow matching.
                    for pkt in test.packets:
                        self._test(STATE_FLOW_MATCH_CHK, pkt)
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
            color_tag = OK_GREEN if result == OK else NG_RED
            msg = color_tag + result + ENDC
            self.logger.info('%s : %s', test.name, msg)
            if result == RYU_INTERNAL_ERROR:
                self.logger.error(traceback.format_exc())

            #TODO: for debug
            #print raw_input("> Enter")

            # Initialize for next test.
            self.test_sw.del_test_flow()
            self.state = STATE_INIT
            self.rcv_msgs = []

        self.test_thread = None
        self.logger.info('---  Test end  ---')

    def _test(self, state, *args):
        test = {STATE_FLOW_INSTALL: self._test_flow_install,
                STATE_FLOW_EXIST_CHK: self._test_flow_exist_check,
                STATE_FLOW_MATCH_CHK: self._test_flow_matching_check,
                STATE_NG_FLOW_INSTALL: self._test_invalid_flow_install}
        self.state = state
        test[state](*args)

    def _test_flow_install(self, flow):
        #self.logger.info("install: [%s]", flow['description'])
        self.test_sw.add_flow(flow_mod=flow['data'])
        self.test_sw.send_barrier_request()
        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, ofproto_v1_3_parser.OFPBarrierReply)

    def _test_flow_exist_check(self, flow_mod):
        def __compare_flow(stats, flow_mod):
            compare_list = [[stats.cookie, flow_mod.cookie],
                            [stats.priority, flow_mod.priority],
                            [stats.flags, flow_mod.flags],
                            [stats.hard_timeout, flow_mod.hard_timeout],
                            [stats.idle_timeout, flow_mod.idle_timeout],
                            [stats.table_id, flow_mod.table_id],
                            [str(stats.instructions),
                             str(flow_mod.instructions)],
                            [str(stats.match), str(flow_mod.match)]]
            for value in compare_list:
                if value[0] != value[1]:
                    return False
            return True

        #self.logger.info("exist check:[%s]", flow_mod['description'])
        self.test_sw.send_flow_stats()
        self._wait()
        for msg in self.rcv_msgs:
            assert isinstance(msg, ofproto_v1_3_parser.OFPFlowStatsReply)
            for stats in msg.body:
                if __compare_flow(stats, flow_mod['data']):
                    return
        raise TestFailure(self.state)

    def _test_flow_matching_check(self, pkt):
        #self.logger.info("send_packet:[%s]",
        #                 pkt['input']['description'])
        send_packet = pkt['input']['data']
        valid_receive_packet = None
        output = pkt['output']
        if output:
            #self.logger.info("valid_receive_packet:[%s]",
            #                 output['description'])
            valid_receive_packet = output['data']
        invalid_receive_packet = None
        packet_in = pkt['packet_in']
        if packet_in:
            #self.logger.info("invalid_receive_packet:[%s]",
            #                 packet_in['description'])
            invalid_receive_packet = packet_in['data']

        self.logger.info("send_packet:[%s]", packet.Packet(send_packet))
        self.logger.debug("valid_receive_packet:[%s]",
                          valid_receive_packet)
        self.logger.debug("invalid_receive_packet:[%s]",
                          invalid_receive_packet)

        # 1. send a packet from the Open vSwitch.
        self.sub_sw.send_packet_out(send_packet)

        # 2. receive a PacketIn message.
        rcv_pkt_model = (invalid_receive_packet
                         if valid_receive_packet is None
                         else valid_receive_packet)
        pkt_in_src_model = (self.test_sw if valid_receive_packet is None
                            else self.sub_sw)

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
                self.logger.info("receive_packet:[%s]", packet.Packet(msg.data))
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

    def _test_invalid_flow_install(self, flows, error):
        # Install test flow.
        for flow in flows:
            #self.logger.info("invalid flow install:[%s]", flow['description'])
            self.test_sw.add_flow(flow_mod=flow['data'])
        if not self.rcv_msgs:
            self.test_sw.send_barrier_request()
            self._wait()

        # Compare error message.
        #self.logger.info("compare error:[%s]", error['description'])
        for err_msg in self.rcv_msgs:
            if str(err_msg) == str(error['data']):
                return
        raise TestFailure(self.state)

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
        if self.state == STATE_FLOW_EXIST_CHK and self.waiter is not None:
            self.rcv_msgs.append(ev.msg)
            if not ev.msg.flags & ev.msg.datapath.ofproto.OFPMPF_REPLY_MORE:
                self.waiter.set()
                hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, handler.MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        if ((self.state == STATE_FLOW_INSTALL
                or self.state == STATE_NG_FLOW_INSTALL)
                and self.waiter is not None):
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
        if self.state != STATE_INIT:
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
        self.dp.send_msg(mod)


class TestSw(OpenFlowSw):
    def __init__(self, dp, logger):
        super(TestSw, self).__init__(dp, logger)
        # Add table miss flow (packet in controller).
        ofp = self.dp.ofproto
        self.add_flow(out_port=ofp.OFPP_CONTROLLER)

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
        self.add_flow(out_port=ofp.OFPP_CONTROLLER)

    def send_flow_stats(self):
        """ Get all flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(self.dp, 0, ofp.OFPTT_ALL,
                                         ofp.OFPP_ANY, ofp.OFPG_ANY,
                                         0, 0, parser.OFPMatch())
        self.dp.send_msg(req)

    def send_barrier_request(self):
        """ send a BARRIER_REQUEST message."""
        parser = self.dp.ofproto_parser
        req = parser.OFPBarrierRequest(self.dp)
        self.dp.send_msg(req)


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
            self.logger.warning(INVALID_PATH % {'path': path})
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
                    self.logger.warning(TEST_FILE_ERROR,
                                        {'file': path,
                                         'detail': e.message})


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
        data = buf.get('data')
        if not data:
            raise ValueError('a test requires a "data" block.')

        # parse 'FLOW_MOD'
        flows = []
        if not 'FLOW_MOD' in data:
            raise ValueError('a test requires a "FLOW_MOD" block '
                             'in the "data" block.')
        for flow in data['FLOW_MOD']:
            flow_desc = flow.get('description')
            if not 'data' in flow:
                raise ValueError('a test requires a "data" field '
                                 'in a "FLOW_MOD" block.')
            msg = __ofp_from_json(
                'OFPFlowMod', flow['data'], 'FLOW_MOD')
            flows.append({'description': flow_desc, 'data': msg})

        # parse 'ERROR'
        error = None
        if 'ERROR' in data:
            error_desc = data['ERROR'].get('description')
            if not 'data' in data['ERROR']:
                raise ValueError('a test requires a "data" field '
                                 'in an "ERROR" block.')
            msg = __ofp_from_json(
                'OFPErrorMsg', data['ERROR']['data'], 'ERROR')
            error = {'description': error_desc, 'data': msg}

        # parse 'packets'
        packets = []
        if not 'packets' in data:
            if not error:
                raise ValueError('a test requires "packet" block '
                                 'when an "ERROR" block does not exist '
                                 'in a "data" block.')
        elif not error:
            for pkt in data['packets']:
                # parse 'input'
                if not 'input' in pkt:
                    raise ValueError('a test requires "input" block '
                                     'when an "ERROR" block does not exist '
                                     'in "data" block.')
                in_desc = pkt['input'].get('description')
                if not 'data' in pkt['input']:
                    raise ValueError('a test requires a "data" field '
                                     'in an "input" block.')
                in_msg = base64.b64decode(pkt['input']['data'])
                in_pkt = {'description': in_desc, 'data': in_msg}

                # parse 'output'
                out_pkt = None
                if 'output' in pkt:
                    out_desc = pkt['output'].get('description')
                    if not 'data' in pkt['output']:
                        raise ValueError('a test requires a "data" field '
                                         'in an "output" block.')
                    out_msg = base64.b64decode(pkt['output']['data'])
                    out_pkt = {'description': out_desc, 'data': out_msg}

                # parse 'PACKET_IN'
                pkt_in_pkt = None
                if 'PACKET_IN' in pkt:
                    pkt_in_desc = pkt['PACKET_IN'].get('description')
                    if not 'data' in pkt['PACKET_IN']:
                        raise ValueError('a test requires a "data" field '
                                         'in a "PACKET_IN" block.')
                    pkt_in_msg = base64.b64decode(pkt['PACKET_IN']['data'])
                    pkt_in_pkt = {'description': pkt_in_desc,
                                  'data': pkt_in_msg}

                if (not out_pkt and not pkt_in_pkt) or \
                        (out_pkt and pkt_in_pkt):
                    raise ValueError(
                        'a test requires either one of "output" or '
                        '"PACKET_IN" block when '
                        'an "ERROR" field does not exist in "data" block.')
                packets.append({'input': in_pkt,
                                'output': out_pkt,
                                'packet_in': pkt_in_pkt})

        return (description, flows, error, packets)


class DummyDatapath(object):
    def __init__(self):
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser
