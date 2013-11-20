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
import inspect
import json
import logging
import os
import struct
import sys
import traceback

# import all packet libraries.
PKT_LIB_PATH = 'ryu.lib.packet'
for modname, mod in sys.modules.iteritems():
    if not modname.startswith(PKT_LIB_PATH) or not mod:
        continue
    for (clsname, cls, ) in inspect.getmembers(mod):
        if not inspect.isclass(cls):
            continue
        exec 'from %s import %s' % (modname, clsname)

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

                      +-----------+
           +----------| target sw | The switch to be tested
           |          +-----------+
    +------------+      (1)   (2)
    | controller |       |     |
    +------------+      (1)   (2)
           |          +-----------+
           +----------| tester sw | Open vSwtich
                      +-----------+

      (X) : port number

    Tests send a packet from port 1 of the tester sw. If the packet
    matched with a flow entry of the target sw, the switch resends the
    packet from port 2, according to the flow entry. then the tester sw
    receives the packet and sends a PacketIn message. if the packet did
    not match, the target sw drops the packet.

    In other words, when a test succeeded, the controller will receive
    a PacketIn message from the tester sw, otherwise it will drops on
    the target sw.

"""

# Log file path.
LOG_FILENAME = './tester.log'

# Command line parameters.
DEBUG_MODE = '--verbose'
ARG_TARGET = '--target='
ARG_TESTER = '--tester='

# Default settings.
DEFAULT_DIRECTORY = './tests'
DEFAULT_TARGET_DPID = dpid_lib.str_to_dpid('0000000000000001')
DEFAULT_TESTER_DPID = dpid_lib.str_to_dpid('0000000000000002')
TESTER_SENDER_PORT = 1
TESTER_RECEIVE_PORT = 2
DEFAULT_TARGET_TABLES = [0]  # target table_id for table-miss test.

WAIT_TIMER = 3  # sec


# Test state.
STATE_INIT = 0
STATE_FLOW_INSTALL = 1
STATE_FLOW_EXIST_CHK = 2
STATE_FLOW_MATCH_CHK = 3
STATE_GET_MATCH_COUNT = 4
STATE_UNMATCH_PKT_SEND = 5
STATE_FLOW_UNMATCH_CHK = 6

# Test result.
OK = 'OK'
NG = 'NG (%(detail)s)'
RYU_INTERNAL_ERROR = '- (Ryu internal error.)'
TEST_FILE_ERROR = '%(file)s : Test file format error (%(detail)s)'
NO_TEST_FILE = 'Test file (*.json) is not found.'
INVALID_PATH = '%(path)s : No such file or directory.'

# Test result details.
FAILURE = 0
ERROR = 1
TIMEOUT = 2
RCV_ERR = 3

MSG = {STATE_INIT:
       {TIMEOUT: 'initialize is failure. no OFPBarrierReply.',
        RCV_ERR: 'initialize is failure. %(err_msg)s'},
       STATE_FLOW_INSTALL:
       {TIMEOUT: 'flows install is failure. no OFPBarrierReply.',
        RCV_ERR: 'flows install is failure. %(err_msg)s'},
       STATE_FLOW_EXIST_CHK:
       {FAILURE: 'expected flow was not installed. %(flows)s',
        TIMEOUT: 'flow existence check is failure. no OFPFlowStatsReply.',
        RCV_ERR: 'flow existence check is failure. %(err_msg)s'},
       STATE_FLOW_MATCH_CHK:
       {FAILURE: 'failed to validate packet. %(rcv_pkt)s',
        TIMEOUT: 'flow matching is failure. no OFPPacketIn.',
        RCV_ERR: 'flow matching is failure. tester SW error. %(err_msg)s'},
       STATE_GET_MATCH_COUNT:
       {TIMEOUT: 'get before table matched count is failure.'
                 ' no OFPTableStatsReply.',
        RCV_ERR: 'get before table matched count is failure. %(err_msg)s'},
       STATE_UNMATCH_PKT_SEND:
       {TIMEOUT: 'unmatch packet sending is failure. no OFPBarrierReply.',
        RCV_ERR: 'unmatch packet sending is failure. %(err_msg)s'},
       STATE_FLOW_UNMATCH_CHK:
       {FAILURE: 'send packet matched with the flow.',
        ERROR: 'send packet did not look up at target tables.',
        TIMEOUT: 'flow unmatching check is failure. no OFPTableStatsReply.',
        RCV_ERR: 'flow unmatching check is failure. %(err_msg)s'}}

ERR_MSG = 'OFPErrorMsg[type=0x%02x, code=0x%02x] received.'


GREEN = '\033[32m'
RED = '\033[31m'
YELLOW = '\033[33m'
END_TAG = '\033[0m'


def coloring(msg, color):
    return color + msg + END_TAG


class TestFailure(RyuException):
    def __init__(self, state, **argv):
        msg = NG % {'detail': (MSG[state][FAILURE] % argv)}
        super(TestFailure, self).__init__(msg=msg)


class TestTimeout(RyuException):
    def __init__(self, state):
        msg = NG % {'detail': MSG[state][TIMEOUT]}
        super(TestTimeout, self).__init__(msg=msg)


class TestReceiveError(RyuException):
    def __init__(self, state, err_msg):
        msg = NG % {'detail': MSG[state][RCV_ERR] %
                   {'err_msg': ERR_MSG % (err_msg.type, err_msg.code)}}
        super(TestReceiveError, self).__init__(msg=msg)


class TestError(RyuException):
    def __init__(self, state, **argv):
        msg = NG % {'detail': (MSG[state][ERROR] % argv)}
        super(TestError, self).__init__(msg=msg)


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
    of_tester = app_mgr.applications['of_tester']
    of_tester.ctlr_thread = hub.spawn(ctlr)
    try:
        hub.joinall([of_tester.ctlr_thread])
    finally:
        app_mgr.close()


if __name__ == "__main__":
    main()


class OfTester(app_manager.RyuApp):
    """ OpenFlowSwitch Tester. """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self):
        super(OfTester, self).__init__()
        params = sys.argv
        debug_mode = bool(DEBUG_MODE in params)
        if debug_mode:
            params.remove(DEBUG_MODE)
        self._set_logger(debug_mode)

        self.target_dpid = self._get_dpid(params, ARG_TARGET)
        self.tester_dpid = self._get_dpid(params, ARG_TESTER)
        self.test_files = (params[1:] if len(params) > 1
                           else [DEFAULT_DIRECTORY])
        self.logger.info('Test files or directory = %s', self.test_files)

        self.target_sw = None
        self.tester_sw = None
        self.state = STATE_INIT
        self.sw_waiter = None
        self.waiter = None
        self.send_msg_xids = []
        self.rcv_msgs = []
        self.ctlr_thread = None
        self.test_thread = hub.spawn(self._test_execute)

    def _get_dpid(self, params, arg_type):
        dpid = (DEFAULT_TARGET_DPID if arg_type == ARG_TARGET
                else DEFAULT_TESTER_DPID)
        for param in params:
            if param.find(arg_type) == 0:
                try:
                    dpid = int(param[len(arg_type):], 16)
                except ValueError as err:
                    self.logger.error('Invarid %s(dpid) parameter. %s',
                                      arg_type, err)
                    sys.exit()
                params.remove(param)
                break
        self.logger.info('%s%s', arg_type, dpid_lib.dpid_to_str(dpid))
        return dpid

    def _set_logger(self, debug_mode):
        self.logger.propagate = False
        s_hdlr = logging.StreamHandler()
        f_hdlr = logging.FileHandler(filename=LOG_FILENAME, mode='w')
        fmt_str = '%(asctime)s [%(levelname)s] %(message)s'
        s_hdlr.setFormatter(logging.Formatter(fmt_str))
        f_hdlr.setFormatter(logging.Formatter(fmt_str))
        self.logger.addHandler(s_hdlr)
        self.logger.addHandler(f_hdlr)
        if debug_mode:
            self.logger.setLevel(logging.DEBUG)

    def close(self):
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
        if dp.id == self.target_dpid:
            self.target_sw = TargetSw(dp, self.logger)
            msg = 'Join target SW.'
        elif dp.id == self.tester_dpid:
            self.tester_sw = TesterSw(dp, self.logger)
            msg = 'Join tester SW.'
        else:
            msg = 'Connect unknown SW.'
        if dp.id:
            self.logger.info('dpid=%s : %s',
                             dpid_lib.dpid_to_str(dp.id), msg)

        if self.target_sw and self.tester_sw:
            if self.sw_waiter is not None:
                self.sw_waiter.set()

    def _unregister_sw(self, dp):
        if dp.id == self.target_dpid:
            del self.target_sw
            self.target_sw = None
            msg = 'Leave target SW.'
        elif dp.id == self.tester_dpid:
            del self.tester_sw
            self.tester_sw = None
            msg = 'Leave tester SW.'
        else:
            msg = 'Disconnect unknown SW.'
        if dp.id:
            self.logger.info('dpid=%s : %s',
                             dpid_lib.dpid_to_str(dp.id), msg)

    def _test_execute(self):
        """ Execute OpenFlowSwitch test. """
        # Parse test pattern from test files.
        tests = TestPatterns(self.test_files, self.logger)
        if not tests:
            msg = coloring(NO_TEST_FILE, YELLOW)
            self.logger.warning(msg)
            self.test_thread = None
            if self.ctlr_thread is not None:
                hub.kill(self.ctlr_thread)
            return

        self.logger.info('--- Test start ---')
        test_keys = tests.keys()
        test_keys.sort()
        for test_name in test_keys:
            if not self.target_sw or not self.tester_sw:
                self.logger.info('waiting for switches connection...')
                self.sw_waiter = hub.Event()
                self.sw_waiter.wait()
                self.sw_waiter = None

            test = tests[test_name]
            # Test execute.
            try:
                # 0. Initialize.
                self._test(STATE_INIT)
                # 1. Install flows.
                for flow in test.flows:
                    self._test(STATE_FLOW_INSTALL, flow)
                    self._test(STATE_FLOW_EXIST_CHK, flow)
                # 2. Check flow matching.
                for pkt in test.packets:
                    if 'egress' in pkt or 'PACKET_IN' in pkt:
                        self._test(STATE_FLOW_MATCH_CHK, pkt)
                    else:
                        before_stats = self._test(STATE_GET_MATCH_COUNT)
                        self._test(STATE_UNMATCH_PKT_SEND, pkt)
                        self._test(STATE_FLOW_UNMATCH_CHK,
                                   before_stats, test.target_tbls)
                result = OK
            except (TestFailure, TestError,
                    TestTimeout, TestReceiveError) as err:
                result = str(err)
            except Exception:
                result = RYU_INTERNAL_ERROR

            # Output test result.
            msg = (coloring(result, GREEN) if result == OK
                   else coloring(result, RED))
            self.logger.info('%s : %s', test_name, msg)
            if test.description:
                self.logger.debug(unicode(test.description))
            if (result == RYU_INTERNAL_ERROR
                    or result == 'An unknown exception'):
                self.logger.error(traceback.format_exc())

            #TODO: for debug
            #print raw_input("> Enter")

            if result != OK and self.state == STATE_INIT:
                break  # Terminate tests.
            hub.sleep(0)

        self.test_thread = None
        if self.ctlr_thread is not None:
            hub.kill(self.ctlr_thread)
        self.logger.info('---  Test end  ---')

    def _test(self, state, *args):
        test = {STATE_INIT: self._test_initialize,
                STATE_FLOW_INSTALL: self._test_flow_install,
                STATE_FLOW_EXIST_CHK: self._test_flow_exist_check,
                STATE_FLOW_MATCH_CHK: self._test_flow_matching_check,
                STATE_GET_MATCH_COUNT: self._test_get_match_count,
                STATE_UNMATCH_PKT_SEND: self._test_unmatch_packet_send,
                STATE_FLOW_UNMATCH_CHK: self._test_flow_unmatching_check}

        self.send_msg_xids = []
        self.rcv_msgs = []

        self.state = state
        return test[state](*args)

    def _test_initialize(self):
        xid = self.target_sw.del_test_flow()
        self.send_msg_xids.append(xid)

        xid = self.target_sw.send_barrier_request()
        self.send_msg_xids.append(xid)

        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, ofproto_v1_3_parser.OFPBarrierReply)

    def _test_flow_install(self, flow):
        xid = self.target_sw.add_flow(flow_mod=flow)
        self.send_msg_xids.append(xid)

        xid = self.target_sw.send_barrier_request()
        self.send_msg_xids.append(xid)

        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, ofproto_v1_3_parser.OFPBarrierReply)

    def _test_flow_exist_check(self, flow_mod):
        xid = self.target_sw.send_flow_stats()
        self.send_msg_xids.append(xid)
        self._wait()

        ng_stats = []
        for msg in self.rcv_msgs:
            assert isinstance(msg, ofproto_v1_3_parser.OFPFlowStatsReply)
            for stats in msg.body:
                result, stats = self._compare_flow(stats, flow_mod)
                if result:
                    return
                else:
                    ng_stats.append(stats)
        raise TestFailure(self.state, flows=', '.join(ng_stats))

    def _test_flow_matching_check(self, pkt):
        def __diff_packets(model_pkt, rcv_pkt):
            msg = []
            for rcv_p in rcv_pkt.protocols:
                if type(rcv_p) != str:
                    model_protocols = model_pkt.get_protocols(type(rcv_p))
                    if len(model_protocols) == 1:
                        model_p = model_protocols[0]
                        diff = []
                        for attr in rcv_p.__dict__:
                            if attr.startswith('_'):
                                continue
                            if callable(attr):
                                continue
                            if hasattr(rcv_p.__class__, attr):
                                continue
                            rcv_attr = repr(getattr(rcv_p, attr))
                            model_attr = repr(getattr(model_p, attr))
                            if rcv_attr != model_attr:
                                diff.append('%s=%s' % (attr, rcv_attr))
                        if diff:
                            msg.append('%s(%s)' %
                                       (rcv_p.__class__.__name__,
                                        ','.join(diff)))
                    else:
                        if (not model_protocols or
                                not str(rcv_p) in str(model_protocols)):
                            msg.append(str(rcv_p))

                else:
                    model_p = ''
                    for p in model_pkt.protocols:
                        if type(p) == str:
                            model_p = p
                            break
                    if model_p != rcv_p:
                        msg.append('str(%s)' % repr(rcv_p))

            if msg:
                return '/'.join(msg)
            else:
                raise RyuException('Internal error.'
                                   ' receive packet is matching.')

        pad_zero = repr('\x00')[1:-1]
        self.logger.debug("send_packet:[%s]", packet.Packet(pkt['ingress']))
        self.logger.debug("egress:[%s]", packet.Packet(pkt.get('egress')))
        self.logger.debug("packet_in:[%s]",
                          packet.Packet(pkt.get('PACKET_IN')))

        # 1. send a packet from the Open vSwitch.
        xid = self.tester_sw.send_packet_out(pkt['ingress'])
        self.send_msg_xids.append(xid)

        # 2. receive a PacketIn message.
        model_pkt = pkt['egress'] if 'egress' in pkt else pkt['PACKET_IN']
        pkt_in_src_model = (self.tester_sw if 'egress' in pkt
                            else self.target_sw)

        timer = hub.Timeout(WAIT_TIMER)
        timeout = False
        log_msg = []
        try:
            while True:
                self._wait(timer=False)

                assert len(self.rcv_msgs) == 1
                msg = self.rcv_msgs[0]
                assert isinstance(msg, ofproto_v1_3_parser.OFPPacketIn)
                self.logger.debug("dpid=%s : receive_packet[%s]",
                                  dpid_lib.dpid_to_str(msg.datapath.id),
                                  packet.Packet(msg.data))

                # 3. confirm which switch sent the message.
                if msg.reason != ofproto_v1_3.OFPR_ACTION:
                    log_msg.append('invalid OFPPacketIn[reason=%d]'
                                   % msg.reason)
                    continue
                if msg.datapath.id != pkt_in_src_model.dp.id:
                    log_msg.append('OFPPacketIn from unexpected SW[dpid=%s]'
                                   % dpid_lib.dpid_to_str(msg.datapath.id))
                    continue
                rcv_pkt_model = repr(model_pkt)[1:-1]
                msg_data = repr(msg.data)[1:-1]
                rcv_pkt = msg_data[:len(rcv_pkt_model)]
                padding = msg_data[len(rcv_pkt_model):]
                padding_model = (pad_zero * ((len(msg_data)
                                 - len(rcv_pkt_model))/len(pad_zero)))
                if rcv_pkt != rcv_pkt_model or padding != padding_model:
                    err_msg = __diff_packets(packet.Packet(model_pkt),
                                             packet.Packet(msg.data))
                    log_msg.append(err_msg)
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
            if log_msg:
                raise TestFailure(self.state,
                                  rcv_pkt=', '.join(log_msg))
            else:
                raise TestTimeout(self.state)

    def _test_get_match_count(self):
        xid = self.target_sw.send_table_stats()
        self.send_msg_xids.append(xid)
        self._wait()
        return {stats.table_id: {'lookup': stats.lookup_count,
                                 'matched': stats.matched_count}
                for msg in self.rcv_msgs for stats in msg.body}

    def _test_unmatch_packet_send(self, pkt):
        # Send a packet from the Open vSwitch.
        self.logger.debug("send_packet:[%s]", packet.Packet(pkt['ingress']))
        self.tester_sw.send_packet_out(pkt['ingress'])

        # Wait OFPBarrierReply.
        xid = self.tester_sw.send_barrier_request()
        self.send_msg_xids.append(xid)
        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, ofproto_v1_3_parser.OFPBarrierReply)

    def _test_flow_unmatching_check(self, before_stats, target_tbls):
        # Check matched packet count.
        xid = self.target_sw.send_table_stats()
        self.send_msg_xids.append(xid)
        self._wait()
        rcv_msgs = {stats.table_id: {'lookup': stats.lookup_count,
                                     'matched': stats.matched_count}
                    for msg in self.rcv_msgs for stats in msg.body}
        lookup = False
        for target_tbl_id in target_tbls:
            before = before_stats[target_tbl_id]
            after = rcv_msgs[target_tbl_id]
            if before['lookup'] < after['lookup']:
                lookup = True
                if before['matched'] < after['matched']:
                    raise TestFailure(self.state)
        if not lookup:
            raise TestError(self.state)

    def _compare_flow(self, stats1, stats2):
        attr_list = ['cookie', 'priority', 'flags', 'hard_timeout',
                     'idle_timeout', 'table_id', 'instructions', 'match']
        for attr in attr_list:
            value1 = getattr(stats1, attr)
            value2 = getattr(stats2, attr)
            if str(value1) != str(value2):
                flow_stats = []
                for attr in attr_list:
                    flow_stats.append('%s=%s' % (attr, getattr(stats1, attr)))
                return False, 'flow_stats(%s)' % ','.join(flow_stats)
        return True, None

    def _wait(self, timer=True):
        """ Wait until specific OFP message received
             or timer is exceeded. """
        assert self.waiter is None

        self.waiter = hub.Event()
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
        if (self.rcv_msgs and isinstance(
                self.rcv_msgs[0], ofproto_v1_3_parser.OFPErrorMsg)):
            raise TestReceiveError(self.state, self.rcv_msgs[0])

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, handler.MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        state_list = [STATE_FLOW_EXIST_CHK]
        if self.state in state_list:
            if self.waiter and ev.msg.xid in self.send_msg_xids:
                self.rcv_msgs.append(ev.msg)
                if not ev.msg.flags & ofproto_v1_3.OFPMPF_REPLY_MORE:
                    self.waiter.set()
                    hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPTableStatsReply, handler.MAIN_DISPATCHER)
    def table_stats_reply_handler(self, ev):
        state_list = [STATE_GET_MATCH_COUNT,
                      STATE_FLOW_UNMATCH_CHK]
        if self.state in state_list:
            if self.waiter and ev.msg.xid in self.send_msg_xids:
                self.rcv_msgs.append(ev.msg)
                if not ev.msg.flags & ofproto_v1_3.OFPMPF_REPLY_MORE:
                    self.waiter.set()
                    hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, handler.MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        state_list = [STATE_INIT,
                      STATE_FLOW_INSTALL,
                      STATE_UNMATCH_PKT_SEND]
        if self.state in state_list:
            if self.waiter and ev.msg.xid in self.send_msg_xids:
                self.rcv_msgs.append(ev.msg)
                self.waiter.set()
                hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        state_list = [STATE_FLOW_MATCH_CHK]
        if self.state in state_list:
            if self.waiter:
                self.rcv_msgs.append(ev.msg)
                self.waiter.set()
                hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [handler.HANDSHAKE_DISPATCHER,
                                             handler.CONFIG_DISPATCHER,
                                             handler.MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        if ev.msg.xid in self.send_msg_xids:
            self.rcv_msgs.append(ev.msg)
            if self.waiter:
                self.waiter.set()
                hub.sleep(0)


class OpenFlowSw(object):
    def __init__(self, dp, logger):
        super(OpenFlowSw, self).__init__()
        self.dp = dp
        self.logger = logger

    def _send_msg(self, msg):
        msg.xid = None
        self.dp.set_xid(msg)
        self.dp.send_msg(msg)
        return msg.xid

    def add_flow(self, flow_mod=None, in_port=None, out_port=None):
        """ Add flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser

        if flow_mod:
            mod = flow_mod
        else:
            match = parser.OFPMatch(in_port=in_port)
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


class TargetSw(OpenFlowSw):
    def __init__(self, dp, logger):
        super(TargetSw, self).__init__(dp, logger)

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

    def send_table_stats(self):
        """ Get table stats. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        req = parser.OFPTableStatsRequest(self.dp, 0)
        return self._send_msg(req)


class TesterSw(OpenFlowSw):
    def __init__(self, dp, logger):
        super(TesterSw, self).__init__(dp, logger)
        # Add packet in flow.
        ofp = self.dp.ofproto
        self.add_flow(in_port=TESTER_RECEIVE_PORT,
                      out_port=ofp.OFPP_CONTROLLER)

    def send_packet_out(self, data):
        """ send a PacketOut message."""
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        actions = [parser.OFPActionOutput(TESTER_SENDER_PORT)]
        out = parser.OFPPacketOut(
            datapath=self.dp, buffer_id=ofp.OFP_NO_BUFFER,
            data=data, in_port=ofp.OFPP_CONTROLLER, actions=actions)
        return self._send_msg(out)


class TestPatterns(dict):
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
                        test_name = path.rstrip('.json')
                        key = (test_name if len(json_list) == 1
                               else test_name + ('_%02d' % i))
                        self[key] = Test(test_json)
                except (ValueError, TypeError) as e:
                    result = (TEST_FILE_ERROR %
                              {'file': path, 'detail': e.message})
                    msg = coloring(result, YELLOW)
                    self.logger.warning(msg)


class Test(object):
    def __init__(self, test_json):
        super(Test, self).__init__()
        (self.description,
         self.flows,
         self.packets,
         self.target_tbls) = self._parse_test(test_json)

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

        # parse 'packets'
        packets = []
        if not 'packets' in buf:
            raise ValueError('a test requires "packet" block.')
        else:
            table_miss_flg = False

            for pkt in buf['packets']:
                pkt_data = {}
                # parse 'ingress'
                if not 'ingress' in pkt:
                    raise ValueError('a test requires "ingress" field.')
                data = eval('/'.join(pkt['ingress']))
                data.serialize()
                pkt_data['ingress'] = str(data.data)

                # parse 'egress'
                out_pkt = None
                if 'egress' in pkt:
                    data = eval('/'.join(pkt['egress']))
                    data.serialize()
                    pkt_data['egress'] = str(data.data)

                # parse 'PACKET_IN'
                pkt_in_pkt = None
                if 'PACKET_IN' in pkt:
                    data = eval('/'.join(pkt['PACKET_IN']))
                    data.serialize()
                    pkt_data['PACKET_IN'] = str(data.data)

                if out_pkt and pkt_in_pkt:
                    raise ValueError(
                        'There must not be both "egress" and "PACKET_IN".')
                if not out_pkt and not pkt_in_pkt:
                    table_miss_flg = True

                packets.append(pkt_data)

            # parse 'target_tables'
            if table_miss_flg:
                target_tbls = ([0] if not 'target_tables' in buf
                               else buf['target_tables'])

        return (description, flows, packets, target_tbls)


class DummyDatapath(object):
    def __init__(self):
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser
