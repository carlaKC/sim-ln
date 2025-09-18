import json
import sys

def convert_to_sim_network(input_file, output_file, expected_payment_amount_msat=3_800_000):
    with open(input_file, 'r') as f:
        data = json.load(f)

    nodes = data.get('nodes', [])
    node_pubkey_index = {node['pub_key']: index for index, node in enumerate(nodes)}

    # Calculate total capacity per node
    node_total_capacity = {}
    for edge in data.get('edges', []):
        node_1_policy = edge.get('node1_policy', None)
        node_2_policy = edge.get('node2_policy', None)

        if not node_1_policy or not node_2_policy:
            continue

        capacity_msat = int(edge['capacity']) * 1000
        node_1_pubkey = edge['node1_pub']
        node_2_pubkey = edge['node2_pub']

        node_total_capacity[node_1_pubkey] = node_total_capacity.get(node_1_pubkey, 0) + capacity_msat
        node_total_capacity[node_2_pubkey] = node_total_capacity.get(node_2_pubkey, 0) + capacity_msat

    # Identify nodes to exclude: total_capacity / 2 < expected_payment_amount_msat * 2
    excluded_nodes = set()
    for pubkey, total_capacity in node_total_capacity.items():
        if total_capacity / 2 < expected_payment_amount_msat * 2:
            excluded_nodes.add(pubkey)
            print(f"Warning: Excluding node {pubkey} because total capacity / 2: {total_capacity / 2} < expected payment * 2: {expected_payment_amount_msat * 2}")

    sim_network = []

    # Sort edges by channel_id to mimic the output of LND's describegraph.
    sorted_edges = sorted(data["edges"], key=lambda chan: int(chan['channel_id']))

    for edge in sorted_edges:
        node_1_policy = edge.get('node1_policy', None)
        node_2_policy = edge.get('node2_policy', None)

        if not node_1_policy or not node_2_policy:
            print(f"Warning: Skipping edge with channel ID {edge['channel_id']} because node1 or node2 policy is null.")
            continue

        # Capacity is expressed in sats.
        capacity_msat = int(edge['capacity']) * 1000
        scid = int(edge['channel_id'])

        node_1_pubkey = edge['node1_pub']
        node_2_pubkey = edge['node2_pub']

        # Filter out channels where either node is excluded
        if node_1_pubkey in excluded_nodes or node_2_pubkey in excluded_nodes:
            print(f"Warning: Skipping channel ID: {scid} because one of the nodes is excluded")
            continue

        node_1_alias = str(node_pubkey_index.get(node_1_pubkey))
        node_2_alias = str(node_pubkey_index.get(node_2_pubkey))
        
        node_1 = {
            "pubkey": node_1_pubkey,
            "alias": node_1_alias,
            "max_htlc_count": 483,
            "max_in_flight_msat": capacity_msat,
            "min_htlc_size_msat": int(node_1_policy['min_htlc']),
            "max_htlc_size_msat": int(node_1_policy['max_htlc_msat']),
            "cltv_expiry_delta": int(node_1_policy['time_lock_delta']),
            "base_fee": int(node_1_policy['fee_base_msat']),
            "fee_rate_prop": int(node_1_policy['fee_rate_milli_msat'])
        }

        node_2 = {
            "pubkey": node_2_pubkey,
            "alias": node_2_alias,
            "max_htlc_count": 483,
            "max_in_flight_msat": capacity_msat,
            "min_htlc_size_msat": int(node_2_policy['min_htlc']),
            "max_htlc_size_msat": int(node_2_policy['max_htlc_msat']),
            "cltv_expiry_delta": int(node_2_policy['time_lock_delta']),
            "base_fee": int(node_2_policy['fee_base_msat']),
            "fee_rate_prop": int(node_2_policy['fee_rate_milli_msat'])
        }

        edge_data = {
                "scid": int(edge['channel_id']),
                "capacity_msat": capacity_msat,
                "node_1": node_1,
                "node_2": node_2
        }

        sim_network.append(edge_data)

    output_data = {"sim_network": sim_network}

    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)

if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python script.py input_file output_file [expected_payment_amount_msat]")
        print("Default expected_payment_amount_msat: 3,800,000")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    expected_payment_amount_msat = int(sys.argv[3]) if len(sys.argv) == 4 else 3_800_000

    convert_to_sim_network(input_file, output_file, expected_payment_amount_msat)
