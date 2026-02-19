/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_AGGREGATION = 0x1234;
const bit<8> NUM_WORKERS = 3;
const bit<32> MAX_CHUNKS = 512;
const bit<16> MCAST_GROUP_ID = 1;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header aggregation_t {
    bit<16> round_id;
    bit<16> worker_id;
    bit<16> chunk_id;
    bit<16> total_chunks;
    bit<16> chunk_len;
    bit<32> value0;
    bit<32> value1;
    bit<32> value2;
    bit<32> value3;
    bit<32> value4;
    bit<32> value5;
    bit<32> value6;
    bit<32> value7;
    bit<32> value8;
    bit<32> value9;
}

struct metadata {
    bit<1> drop;
    bit<32> reg_sum0;
    bit<32> reg_sum1;
    bit<32> reg_sum2;
    bit<32> reg_sum3;
    bit<32> reg_sum4;
    bit<32> reg_sum5;
    bit<32> reg_sum6;
    bit<32> reg_sum7;
    bit<32> reg_sum8;
    bit<32> reg_sum9;
    bit<8> reg_count;
    bit<8> reg_bitmap;
    bit<16> reg_round;
}

struct headers {
    ethernet_t ethernet;
    aggregation_t aggregation;
    ipv4_t ipv4;
    udp_t udp;
}

register<bit<32>>(MAX_CHUNKS) sum0_reg;
register<bit<32>>(MAX_CHUNKS) sum1_reg;
register<bit<32>>(MAX_CHUNKS) sum2_reg;
register<bit<32>>(MAX_CHUNKS) sum3_reg;
register<bit<32>>(MAX_CHUNKS) sum4_reg;
register<bit<32>>(MAX_CHUNKS) sum5_reg;
register<bit<32>>(MAX_CHUNKS) sum6_reg;
register<bit<32>>(MAX_CHUNKS) sum7_reg;
register<bit<32>>(MAX_CHUNKS) sum8_reg;
register<bit<32>>(MAX_CHUNKS) sum9_reg;
register<bit<8>>(MAX_CHUNKS) count_reg;
register<bit<8>>(MAX_CHUNKS) bitmap_reg;
register<bit<16>>(MAX_CHUNKS) round_reg;

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_AGGREGATION: parse_aggregation;
            default: accept;
        }
    }

    state parse_aggregation {
        packet.extract(hdr.aggregation);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition parse_udp;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        meta.drop = 1;
    }

    action ipv4_forward(bit<48> dst_mac, bit<48> src_mac, bit<9> port) {
        hdr.ethernet.dstAddr = dst_mac;
        hdr.ethernet.srcAddr = src_mac;
        standard_metadata.egress_spec = port;
        if (hdr.ipv4.ttl > 0) {
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        } else {
            meta.drop = 1;
        }
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        meta.drop = 0;

        if (hdr.aggregation.isValid()) {
            bit<32> idx = (bit<32>)hdr.aggregation.chunk_id;
            bit<8> worker_bit = 0;

            if ((bit<8>)hdr.aggregation.worker_id == 1) {
                worker_bit = 1;
            } else if ((bit<8>)hdr.aggregation.worker_id == 2) {
                worker_bit = 2;
            } else if ((bit<8>)hdr.aggregation.worker_id == 3) {
                worker_bit = 4;
            } else {
                meta.drop = 1;
            }

            if (meta.drop == 0) {
                sum0_reg.read(meta.reg_sum0, idx);
                sum1_reg.read(meta.reg_sum1, idx);
                sum2_reg.read(meta.reg_sum2, idx);
                sum3_reg.read(meta.reg_sum3, idx);
                sum4_reg.read(meta.reg_sum4, idx);
                sum5_reg.read(meta.reg_sum5, idx);
                sum6_reg.read(meta.reg_sum6, idx);
                sum7_reg.read(meta.reg_sum7, idx);
                sum8_reg.read(meta.reg_sum8, idx);
                sum9_reg.read(meta.reg_sum9, idx);
                count_reg.read(meta.reg_count, idx);
                bitmap_reg.read(meta.reg_bitmap, idx);
                round_reg.read(meta.reg_round, idx);

                if (meta.reg_round != hdr.aggregation.round_id) {
                    meta.reg_sum0 = 0;
                    meta.reg_sum1 = 0;
                    meta.reg_sum2 = 0;
                    meta.reg_sum3 = 0;
                    meta.reg_sum4 = 0;
                    meta.reg_sum5 = 0;
                    meta.reg_sum6 = 0;
                    meta.reg_sum7 = 0;
                    meta.reg_sum8 = 0;
                    meta.reg_sum9 = 0;
                    meta.reg_count = 0;
                    meta.reg_bitmap = 0;
                    meta.reg_round = hdr.aggregation.round_id;
                }

                if ((meta.reg_bitmap & worker_bit) == 0) {
                    meta.reg_sum0 = meta.reg_sum0 + hdr.aggregation.value0;
                    meta.reg_sum1 = meta.reg_sum1 + hdr.aggregation.value1;
                    meta.reg_sum2 = meta.reg_sum2 + hdr.aggregation.value2;
                    meta.reg_sum3 = meta.reg_sum3 + hdr.aggregation.value3;
                    meta.reg_sum4 = meta.reg_sum4 + hdr.aggregation.value4;
                    meta.reg_sum5 = meta.reg_sum5 + hdr.aggregation.value5;
                    meta.reg_sum6 = meta.reg_sum6 + hdr.aggregation.value6;
                    meta.reg_sum7 = meta.reg_sum7 + hdr.aggregation.value7;
                    meta.reg_sum8 = meta.reg_sum8 + hdr.aggregation.value8;
                    meta.reg_sum9 = meta.reg_sum9 + hdr.aggregation.value9;
                    meta.reg_count = meta.reg_count + 1;
                    meta.reg_bitmap = meta.reg_bitmap | worker_bit;

                    if (meta.reg_count == NUM_WORKERS) {
                        hdr.aggregation.value0 = meta.reg_sum0;
                        hdr.aggregation.value1 = meta.reg_sum1;
                        hdr.aggregation.value2 = meta.reg_sum2;
                        hdr.aggregation.value3 = meta.reg_sum3;
                        hdr.aggregation.value4 = meta.reg_sum4;
                        hdr.aggregation.value5 = meta.reg_sum5;
                        hdr.aggregation.value6 = meta.reg_sum6;
                        hdr.aggregation.value7 = meta.reg_sum7;
                        hdr.aggregation.value8 = meta.reg_sum8;
                        hdr.aggregation.value9 = meta.reg_sum9;
                        hdr.aggregation.worker_id = 0;
                        standard_metadata.mcast_grp = MCAST_GROUP_ID;

                        meta.reg_sum0 = 0;
                        meta.reg_sum1 = 0;
                        meta.reg_sum2 = 0;
                        meta.reg_sum3 = 0;
                        meta.reg_sum4 = 0;
                        meta.reg_sum5 = 0;
                        meta.reg_sum6 = 0;
                        meta.reg_sum7 = 0;
                        meta.reg_sum8 = 0;
                        meta.reg_sum9 = 0;
                        meta.reg_count = 0;
                        meta.reg_bitmap = 0;
                    } else {
                        meta.drop = 1;
                    }
                } else {
                    meta.drop = 1;
                }

                sum0_reg.write(idx, meta.reg_sum0);
                sum1_reg.write(idx, meta.reg_sum1);
                sum2_reg.write(idx, meta.reg_sum2);
                sum3_reg.write(idx, meta.reg_sum3);
                sum4_reg.write(idx, meta.reg_sum4);
                sum5_reg.write(idx, meta.reg_sum5);
                sum6_reg.write(idx, meta.reg_sum6);
                sum7_reg.write(idx, meta.reg_sum7);
                sum8_reg.write(idx, meta.reg_sum8);
                sum9_reg.write(idx, meta.reg_sum9);
                count_reg.write(idx, meta.reg_count);
                bitmap_reg.write(idx, meta.reg_bitmap);
                round_reg.write(idx, meta.reg_round);
            }
        } else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        } else {
            meta.drop = 1;
        }

        if (meta.drop == 1) {
            mark_to_drop(standard_metadata);
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.aggregation.isValid()) {
            hdr.ipv4.srcAddr = 0x0a0001fe; // 10.0.1.254
            hdr.ipv4.ttl = 64;

            if (standard_metadata.egress_port == 1) {
                hdr.ethernet.srcAddr = 0x000000000001;
                hdr.ethernet.dstAddr = 0x000000000101;
                hdr.ipv4.dstAddr = 0x0a000101; // 10.0.1.1
                hdr.udp.dstPort = 5001;
            } else if (standard_metadata.egress_port == 2) {
                hdr.ethernet.srcAddr = 0x000000000002;
                hdr.ethernet.dstAddr = 0x000000000102;
                hdr.ipv4.dstAddr = 0x0a000102; // 10.0.1.2
                hdr.udp.dstPort = 5002;
            } else if (standard_metadata.egress_port == 3) {
                hdr.ethernet.srcAddr = 0x000000000003;
                hdr.ethernet.dstAddr = 0x000000000103;
                hdr.ipv4.dstAddr = 0x0a000103; // 10.0.1.3
                hdr.udp.dstPort = 5003;
            }
        }
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.aggregation);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
