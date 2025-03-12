import ctypes
import ipaddress
import logging
import os
import pyverbs
import socket
import struct
import sys
import threading
import time

from pyverbs.device import rdma_get_devices
from pyverbs.enums import *


PORT = 12345
BUFFER_SIZE = 60816028


class QpConnectionData(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('qp_num', ctypes.c_uint32),
        ('rkey',   ctypes.c_uint32),
        ('addr',   ctypes.c_uint64),
        ('gid',    ctypes.c_ubyte * 16)
    ]


callback = None
keep_polling: bool = True
def poll_cq(cq: pyverbs.cq.CQ, mr: pyverbs.mr.MR) -> None:
    global keep_polling

    while keep_polling:
        wc_num, wc_list = cq.poll(num_entries=1)
        if wc_num > 0:
            for wc in wc_list:
                logging.info(f"CQE: wr_id={wc.wr_id}, status={wc.status}")
                if wc.wr_id == 0xdead:
                    if callback is not None:
                        callback(mr.read(length=BUFFER_SIZE, offset=0))
                    keep_polling = False


def recvn(sock: socket.socket, n: int) -> bytes:
    data = b''

    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    
    return data


# The SoftRoCE interface name is passed as argument
# The PORT constant is the TCP port where the server is listening
def read_weights(iface: str) -> None:
    devices_list = pyverbs.device.rdma_get_devices()
    found = False
    for device in devices_list:
        device_name_str = device.name.decode('utf-8')
        if device_name_str == iface:
            found = True
            break
    if not found:
        raise Exception(f"Interface {iface} not found.")

    # TODO: Write your logic here!
    
    print(f"[CLIENT] Found RDMA interface: {iface}")

    # Step 1: Setup RDMA Device, PD, and CQ
    ctx = Context(name=iface)
    pd = PD(ctx)
    cq = CQ(ctx)

    # Step 2: Allocate Memory Region (MR)
    buffer = bytearray(BUFFER_SIZE)
    mr = MR(pd, buffer, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ)

    # Step 3: Create Queue Pair (QP)
    qp_init_attr = QPInitAttr(
        send_cq=cq,
        recv_cq=cq,
        qp_type=IBV_QPT_RC
    )
    qp = QP(pd, qp_init_attr)

    print(f"[CLIENT] Created QP: {qp.qp_num}")

    # Step 4: Connect to RDMA Server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("10.0.100.1", PORT))  # Change to actual RDMA server IP
    print("[CLIENT] Connected to RDMA server")

    # Step 5: Exchange QP Info
    local_qp_data = QpConnectionData(
        qp_num=qp.qp_num,
        rkey=mr.rkey,
        addr=ctypes.addressof(mr.buf),
        gid=(ctypes.c_ubyte * 16)(*([0] * 16))  # Placeholder GID
    )
    sock.send(local_qp_data)

    remote_qp_data = recvn(sock, ctypes.sizeof(QpConnectionData))
    remote_qp = QpConnectionData.from_buffer_copy(remote_qp_data)

    print(f"[CLIENT] Received remote QP: {remote_qp.qp_num}")

    # Step 6: Modify QP to RTR (Ready to Receive)
    qp_attr = QPAttr(qp_state=IBV_QPS_RTR, dest_qp_num=remote_qp.qp_num)
    qp.modify(qp_attr, IBV_QP_STATE | IBV_QP_AV)

    # Step 7: Modify QP to RTS (Ready to Send)
    qp_attr.qp_state = IBV_QPS_RTS
    qp.modify(qp_attr, IBV_QP_STATE)

    print(f"[CLIENT] QP moved to RTS state")

    # Step 8: RDMA Read Operation (Client fetches weights from Server)
    print("[CLIENT] Initiating RDMA Read...")

    sge = SGE(addr=mr.buf, length=BUFFER_SIZE, lkey=mr.lkey)
    wr = SendWR(
        wr_id=0xdead,
        sg=[sge],
        opcode=IBV_WR_RDMA_READ,
        send_flags=IBV_SEND_SIGNALED,
        rdma_rkey=remote_qp.rkey,
        rdma_remote_addr=remote_qp.addr
    )

    qp.post_send(wr)
    print("[CLIENT] RDMA Read Request Sent")

    # Step 9: Poll Completion Queue
    poll_cq(cq, mr)

    print("[CLIENT] RDMA Read Complete. Model Weights Loaded.")
    
    # Close TCP Connection
    sock.close()

if __name__ == "__main__":
    read_weights("rxe1")  # Change this to your actual RDMA device interface
