from scapy.all import Packet, Ether, IP, bind_layers
from scapy.fields import BitField

# Constants to match P4
TYPE_IPV4 = 0x800
TYPE_AGGREGATION = 0x1234


class AggregationInNetwork(Packet):
    name = "AggregationInNetwork"
    fields_desc = [
        BitField("round_id", 0, 16),
        BitField("worker_id", 0, 16),
        BitField("chunk_id", 0, 16),
        BitField("total_chunks", 0, 16),
        BitField("chunk_len", 1, 16),
        BitField("value0", 0, 32),
        BitField("value1", 0, 32),
        BitField("value2", 0, 32),
        BitField("value3", 0, 32),
        BitField("value4", 0, 32),
        BitField("value5", 0, 32),
        BitField("value6", 0, 32),
        BitField("value7", 0, 32),
        BitField("value8", 0, 32),
        BitField("value9", 0, 32),
    ]


bind_layers(Ether, AggregationInNetwork, type=TYPE_AGGREGATION)
bind_layers(Ether, IP, type=TYPE_IPV4)
bind_layers(AggregationInNetwork, IP)
