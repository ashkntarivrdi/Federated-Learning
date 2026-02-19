import argparse
import sys
import threading
import time
from typing import Dict

import numpy as np
from scapy.all import Ether, IP, UDP, get_if_hwaddr, sendp, sniff
from scapy.packet import Packet

from config.config import AppConfig, load_config
from ml.data_loader import load_multi_mnist
from ml.model import SimpleNeuralNetwork
from protocol.layers_in_network import AggregationInNetwork, TYPE_AGGREGATION
from utils.network import get_if
from utils.tracker import ResultsTracker

HOSTS = {
    1: {"ip": "10.0.1.1", "mac": "00:00:00:00:01:01", "gw_mac": "00:00:00:00:00:01"},
    2: {"ip": "10.0.1.2", "mac": "00:00:00:00:01:02", "gw_mac": "00:00:00:00:00:02"},
    3: {"ip": "10.0.1.3", "mac": "00:00:00:00:01:03", "gw_mac": "00:00:00:00:00:03"},
}

CHUNK_SIZE = 10
WEIGHT_SCALE = 10000
WEIGHT_OFFSET = 500000
INTER_PACKET_GAP_SEC = 0.001
PRE_SEND_BARRIER_SEC = 0
AGGREGATION_WAIT_TIMEOUT_SEC = 120


class WorkerInNetwork:
    def __init__(self, worker_id: int, config: AppConfig):
        self.worker_id = worker_id
        self.config = config
        self.iface = get_if()

        self.results_tracker = ResultsTracker(worker_id)
        self.model = SimpleNeuralNetwork(
            input_size=self.config.model_params.input_size,
            hidden_size=self.config.model_params.hidden_size,
            output_size=self.config.model_params.output_size,
        )

        if worker_id not in HOSTS:
            raise ValueError(f"Unknown worker_id {worker_id}. Update HOSTS mapping.")
        self.host_info = HOSTS[worker_id]
        self.src_mac = get_if_hwaddr(self.iface)

        self.received_chunks: Dict[int, np.ndarray] = {}
        self.expected_total_chunks = 0
        self.expected_total_elements = 0
        self.received_event = threading.Event()
        self.rx_lock = threading.Lock()
        self.current_round = 0

        self.receiver_thread = threading.Thread(target=self._packet_receiver, daemon=True)
        self.receiver_thread.start()

    def _packet_receiver(self):
        print(f"Starting packet receiver on {self.iface}...")
        try:
            sniff(
                filter="ether proto 0x1234",
                iface=self.iface,
                prn=self._handle_packet,
                store=False,
            )
        except Exception as e:
            print(f"Error in packet receiver: {e}", file=sys.stderr)

    def _handle_packet(self, pkt: Packet):
        if AggregationInNetwork not in pkt:
            return

        agg = pkt[AggregationInNetwork]
        if int(agg.worker_id) != 0:
            return
        if int(agg.round_id) != self.current_round:
            return

        chunk_id = int(agg.chunk_id)
        total_chunks = int(agg.total_chunks)
        chunk_len = int(agg.chunk_len)
        num_workers = self.config.protocol.num_workers
        encoded_sums = np.array([
            int(agg.value0),
            int(agg.value1),
            int(agg.value2),
            int(agg.value3),
            int(agg.value4),
            int(agg.value5),
            int(agg.value6),
            int(agg.value7),
            int(agg.value8),
            int(agg.value9),
        ], dtype=np.float64)
        decoded_chunk = (encoded_sums - (num_workers * WEIGHT_OFFSET)) / (WEIGHT_SCALE * num_workers)

        with self.rx_lock:
            if self.expected_total_chunks == 0:
                self.expected_total_chunks = total_chunks
            if chunk_len <= 0 or chunk_len > CHUNK_SIZE:
                return
            current_total_elements = (total_chunks - 1) * CHUNK_SIZE + chunk_len
            if self.expected_total_elements == 0:
                self.expected_total_elements = current_total_elements

            self.received_chunks[chunk_id] = decoded_chunk[:chunk_len]

            if self.expected_total_chunks > 0 and len(self.received_chunks) == self.expected_total_chunks:
                ordered = [self.received_chunks[i] for i in range(self.expected_total_chunks)]
                self.model.set_weights(np.concatenate(ordered).astype(np.float32))
                # print(
                #     f"Round {self.current_round + 1}: received all aggregated chunks "
                #     f"({len(self.received_chunks)}/{self.expected_total_chunks} chunks)"
                # )
                self.received_event.set()

    def send_model_weights(self):
        weights = self.model.get_weights()
        total_chunks = int(np.ceil(weights.size / CHUNK_SIZE))
        total_packets = total_chunks
        # print(
        #     f"Round {self.current_round + 1}: sending {total_chunks} chunks to switch, "
        #     f"total_packets={total_packets}"
        # )

        dst_ip = "10.0.1.254"

        for chunk_id in range(total_chunks):
            start = chunk_id * CHUNK_SIZE
            end = min(start + CHUNK_SIZE, weights.size)
            chunk_len = end - start
            chunk_vals = np.zeros(CHUNK_SIZE, dtype=np.float32)
            if chunk_len > 0:
                chunk_vals[:chunk_len] = weights[start:end]

            encoded_vals = []
            for i in range(CHUNK_SIZE):
                encoded_value = int(np.round(chunk_vals[i] * WEIGHT_SCALE)) + WEIGHT_OFFSET
                if encoded_value < 0:
                    encoded_value = 0
                if encoded_value > 0xFFFFFFFF:
                    encoded_value = 0xFFFFFFFF
                encoded_vals.append(encoded_value)

            pkt = (
                Ether(src=self.src_mac, dst=self.host_info["gw_mac"], type=TYPE_AGGREGATION)
                / AggregationInNetwork(
                    round_id=self.current_round,
                    worker_id=self.worker_id,
                    chunk_id=chunk_id,
                    total_chunks=total_chunks,
                    chunk_len=chunk_len,
                    value0=encoded_vals[0],
                    value1=encoded_vals[1],
                    value2=encoded_vals[2],
                    value3=encoded_vals[3],
                    value4=encoded_vals[4],
                    value5=encoded_vals[5],
                    value6=encoded_vals[6],
                    value7=encoded_vals[7],
                    value8=encoded_vals[8],
                    value9=encoded_vals[9],
                )
                / IP(src=self.host_info["ip"], dst=dst_ip)
                / UDP(sport=5000 + self.worker_id, dport=5000)
            )
            sendp(pkt, iface=self.iface, verbose=False)
            time.sleep(INTER_PACKET_GAP_SEC)

    def run_training_round(self):
        print(f"Loading data for round {self.current_round + 1}...")
        (X_train, y_train), (X_test, y_test) = load_multi_mnist(
            digits=[1, 2, 3],
            num_features=self.config.model_params.input_size,
            num_samples=self.config.training.samples_per_worker,
            num_workers=self.config.protocol.num_workers,
        )

        print(f"Training on {len(X_train)} samples...")
        self.model.train(
            X_train,
            y_train,
            epochs=self.config.training.epochs_per_round,
            learning_rate=self.config.training.learning_rate,
            momentum=self.config.training.momentum,
        )

        y_pred_probs = self.model.forward(X_train)
        y_one_hot = np.eye(self.config.model_params.output_size)[y_train]
        loss = self.model.compute_loss(y_one_hot, y_pred_probs)
        train_acc = self.model.evaluate(X_train, y_train)
        self.results_tracker.add_round_results(self.current_round, loss, train_acc)
        print(f"Round {self.current_round + 1} - Pre-aggregation training accuracy: {train_acc:.4f}")

        # print(f"Round {self.current_round + 1}: waiting {PRE_SEND_BARRIER_SEC}s barrier before send")
        time.sleep(PRE_SEND_BARRIER_SEC)
        self.send_model_weights()
        print("Waiting for in-network aggregated model from switch...")

        if not self.received_event.wait(timeout=AGGREGATION_WAIT_TIMEOUT_SEC):
            with self.rx_lock:
                missing = []
                if self.expected_total_chunks > 0:
                    missing = [i for i in range(self.expected_total_chunks) if i not in self.received_chunks]
            raise TimeoutError(
                f"Round {self.current_round + 1} aggregation timeout after "
                f"{AGGREGATION_WAIT_TIMEOUT_SEC}s. Missing chunk_ids: {missing[:20]}"
            )

        post_acc = self.model.evaluate(X_test, y_test)
        print(f"Round {self.current_round + 1} - Post-aggregation test accuracy: {post_acc:.4f}\n")

    def start(self):
        num_rounds = self.config.training.rounds
        for r in range(num_rounds):
            self.current_round = r
            print(f"\n{'=' * 15} Round {r + 1}/{num_rounds} {'=' * 15}")

            with self.rx_lock:
                self.received_chunks.clear()
                self.expected_total_chunks = 0
                self.expected_total_elements = 0
                self.received_event.clear()

            self.run_training_round()
            time.sleep(2)

        self.results_tracker.save_to_file(filename=f"worker_{self.worker_id}_in_network_results.json")
        print("\nAll training rounds complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Federated Learning Worker Node (In-network Aggregation)")
    parser.add_argument("worker_id", type=int, help="Worker ID (1-indexed)")
    parser.add_argument("--config", type=str, default="config/config.json", help="Path to the configuration file")
    args = parser.parse_args()

    try:
        app_config = load_config(args.config)
    except (FileNotFoundError, KeyError, TypeError):
        sys.exit(1)

    np.random.seed(42 + args.worker_id)

    worker = WorkerInNetwork(worker_id=args.worker_id, config=app_config)
    worker.start()
