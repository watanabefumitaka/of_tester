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
import datetime  #TODO: for capture log
import inspect
import json
import logging
import os
import struct
import subprocess  #TODO: for capture log
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


# Command line parameters.
DEBUG_MODE = '--verbose'
ARG_TARGET = '--target='
ARG_TESTER = '--tester='
ARG_CAP_IF = '--cap-if='  #TODO: for capture log

DEFAULT_DIRECTORY = './tests'
DEFAULT_TARGET_DPID = dpid_lib.str_to_dpid('0000000000000001')
DEFAULT_TESTER_DPID = dpid_lib.str_to_dpid('0000000000000002')
SUB_SW_SENDER_PORT = 1
CAP_LOG_DIRECTORY = '/tmp/of_tester_logs/'  #TODO: for capture log

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

MSG = {STATE_INIT:
       {TIMEOUT: 'initialize is failure. no OFPBarrierReply.',
        RCV_ERR: 'initialize is failure. %(err_msg)s'},
       STATE_FLOW_INSTALL:
       {TIMEOUT: 'flows install is failure. no OFPBarrierReply.',
        RCV_ERR: 'flows install is failure. %(err_msg)s'},
       STATE_FLOW_EXIST_CHK:
       {FAILURE: 'expected flow was not installed.',
        TIMEOUT: 'flow existence check is failure. no OFPFlowStatsReply.',
        RCV_ERR: 'flow existence check is failure. %(err_msg)s'},
       STATE_FLOW_MATCH_CHK:
       {FAILURE: 'failed to validate egress packet. %(rcv_pkt)s',
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
       {FAILURE: 'send packet was matched with the flow.',
        TIMEOUT: 'flow unmatching check is failure. no OFPTableStatsReply.',
        RCV_ERR: 'flow unmatching check is failure. %(err_msg)s'},
       STATE_NG_FLOW_INSTALL:
       {FAILURE: 'invalid flows install is failure. no expected OFPErrorMsg.',
        TIMEOUT: 'invalid flows install is failure. no OFPBarrierReply.'}}

ERR_MSG = 'OFPErrorMsg received. type=0x%02x code=0x%02x data=%s'


GREEN = '\033[32m'
RED = '\033[31m'
YELLOW = '\033[33m'
END_TAG = '\033[0m'


def coloring(msg, color):
    return color + msg + END_TAG


class TestFailure(RyuException):
    def __init__(self, state, **argv):
        msg = NG % {'detail': (MSG[state][FAILURE] % argv)}
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
        self.cap_ifs = self._get_capture_if(params)  #TODO: for capture log
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

        #TODO: for capture log
        caplog_dir = None
        if self.cap_ifs:
            if not os.path.exists(CAP_LOG_DIRECTORY):
                os.system('mkdir %s' % CAP_LOG_DIRECTORY)
            caplog_dir = (CAP_LOG_DIRECTORY +
                          datetime.datetime.today().strftime("%Y%m%d_%H%M%S")
                          + '/')
            os.system('mkdir %s' % caplog_dir)
            self.logger.info('Output capture logs to [%s]', caplog_dir)

        self.test_thread = hub.spawn(self._test_execute, caplog_dir)

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

    #TODO: for capture log
    def _get_capture_if(self, params):
        ifs = []
        for param in params:
            if param.find(ARG_CAP_IF) == 0:
                ifs = param[len(ARG_CAP_IF):].split(',')
                params.remove(param)
                break
        if ifs:
            self.logger.info('%s%s', ARG_CAP_IF, ifs)
        return ifs

    def _set_logger(self, debug_mode):
        self.logger.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '%(asctime)s [%(levelname)s] %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        self.logger.addHandler(hdlr)
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

    def _test_execute(self, caplog_dir):
        """ Execute OpenFlowSwitch test. """
        # Parse test pattern from test files.
        tests = TestPatterns(self.test_files, self.logger)
        if not tests:
            msg = coloring(NO_TEST_FILE, YELLOW)
            self.logger.warning(msg)
            return

        test_keys = tests.keys()
        test_keys.sort()
        self.logger.info('--- Test start ---')
        for test_name in test_keys:
            if self.target_sw is None or self.tester_sw is None:
                self.logger.info('waiting for switches connection...')
                self.sw_waiter = hub.Event()
                self.sw_waiter.wait()
                self.sw_waiter = None

            #TODO: for capture log
            cap_logs = []
            if self.cap_ifs:
                for cap_if in self.cap_ifs:
                    cap_logs.append(CaptureLog(cap_if, test_name, caplog_dir))

            test = tests[test_name]
            # Test execute.
            try:
                # 0. Initialize.
                self._test(STATE_INIT)

                if not test.error:
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

            #TODO: for capture log
            for cap_log in cap_logs:
                cap_log.stop()

            # Output test result.
            msg = (coloring(result, GREEN) if result == OK
                   else coloring(result, RED))
            self.logger.info('%s : %s', test_name, msg)
            if result == RYU_INTERNAL_ERROR:
                self.logger.error(traceback.format_exc())

            #TODO: for debug
            #print raw_input("> Enter")

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
                STATE_FLOW_UNMATCH_CHK: self._test_flow_unmatching_check,
                STATE_NG_FLOW_INSTALL: self._test_invalid_flow_install}

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
        for msg in self.rcv_msgs:
            assert isinstance(msg, ofproto_v1_3_parser.OFPFlowStatsReply)
            for stats in msg.body:
                if self._compare_flow(stats, flow_mod):
                    return
        raise TestFailure(self.state)

    def _test_flow_matching_check(self, pkt):
        def __diff_packets(model_pkt, rcv_pkt):
            msg = []
            for rcv_p in rcv_pkt.protocols:
                if type(rcv_p) != str:
                    model_p = model_pkt.get_protocol(type(rcv_p))
                    if model_p:
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
                        msg.append(str(rcv_p))
                else:
                    rcv_p = ''
                    for p in rcv_pkt.protocols:
                        if type(p) == str:
                            rcv_p = p
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

                # 3. confirm which switch sent the message.
                if msg.datapath.id != pkt_in_src_model.dp.id:
                    self.logger.debug("received PacketIn from unsuitable SW.")
                    continue
                self.logger.debug("receive_packet:[%s]",
                                  packet.Packet(msg.data))
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
        return {stats.table_id: stats.matched_count
                for msg in self.rcv_msgs for stats in msg.body}

    def _test_unmatch_packet_send(self, pkt):
        # send a packet from the Open vSwitch.
        self.logger.debug("send_packet:[%s]", packet.Packet(pkt['ingress']))
        self.tester_sw.send_packet_out(pkt['ingress'])

        # wait OFPBarrierReply.
        xid = self.tester_sw.send_barrier_request()
        self.send_msg_xids.append(xid)
        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, ofproto_v1_3_parser.OFPBarrierReply)

    def _test_flow_unmatching_check(self, before_stats):
        # check match packet count
        xid = self.target_sw.send_table_stats()
        self.send_msg_xids.append(xid)
        self._wait()
        rcv_msgs = {stats.table_id: stats.matched_count
                    for msg in self.rcv_msgs for stats in msg.body}
        if before_stats != rcv_msgs:
            raise TestFailure(self.state)

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
            msg_data = msg.data[head_len:64]
            error_data = pattern.data[head_len:64]
            if msg_data != error_data:
                return False
            return True

        # Install test flow.
        for flow in flows:
            xid = self.target_sw.add_flow(flow_mod=flow)
            self.send_msg_xids.append(xid)
        if not self.rcv_msgs:
            xid = self.target_sw.send_barrier_request()
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
                      STATE_NG_FLOW_INSTALL,
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


#TODO: for capture log
class CaptureLog(object):
    def __init__(self, if_name, test_name, dir_path):
        test_name = test_name.replace('.', '').replace('/', '\\')
        file_name = '%s_%s.cap' % (test_name, if_name)
        self.process = subprocess.Popen(
            ('sudo', 'tcpdump', '-n', '-i', if_name, '-s 0', '-w',
             dir_path + file_name), stdout=subprocess.PIPE)

    def stop(self):
        self.process.terminate()


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
        self.add_flow(out_port=ofp.OFPP_CONTROLLER)

    def send_packet_out(self, data):
        """ send a PacketOut message."""
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        actions = [parser.OFPActionOutput(SUB_SW_SENDER_PORT)]
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
                               else test_name + ('_%d' % i))
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
                # parse 'ingress'
                if not 'ingress' in pkt:
                    raise ValueError('a test requires "ingress" field '
                                     'when an "ERROR" block does not exist.')
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
                        'There must not be both "egress" and "PACKET_IN"'
                        ' field when an "ERROR" block does not exist.')
                packets.append(pkt_data)

        return (description, flows, error, packets)


class DummyDatapath(object):
    def __init__(self):
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser
