import pyshark
from packet_classes import PhysicalLayer, DataLinkLayer, NetworkLayer, TransportLayer, SessionLayer, PresentationLayer, ApplicationLayer, OSIDataLinkLayer
from pprint import pprint

def capture_live_traffic(interface_to_use: str, num_packets: int) -> pyshark.RemoteCapture | pyshark.FileCapture | pyshark.InMemCapture | pyshark.LiveCapture | pyshark.LiveRingCapture:
    interface_capture = pyshark.LiveCapture(interface=interface_to_use)
    interface_capture.sniff(packet_count=num_packets)
    return interface_capture


def instantiate_osi_layers(**kwargs) -> dict:
    return kwargs


def get_layer_info(layer, capture_interface) -> dict:
    return layer.get_complete_layer_info(capture_interface)


def get_layer_attributes(info, layer_list) -> dict:
    return info.get_attribute_from_layer(layer_list)


def update_combine_dict(combine_dict, packet_key_name, layer_name, attributes) -> dict:
    try:
        combine_dict[packet_key_name].update({layer_name: attributes[packet_key_name]})
    except KeyError:
        combine_dict[packet_key_name].update({layer_name: None})


def extract_substring(iterable: list | dict | tuple | set, identifier: str) -> str:
    new_substring = str()
    for char in iterable:
        if char != identifier:
            new_substring += char
        else:
            break
    return new_substring


def format_attribute_dict(attribute_dict: dict) -> dict:
    for index in range(len(attribute_dict)):
        packet_num = f'Packet {index + 1}'
        for key, value in attribute_dict[packet_num].items():
            if value != None:
                for inner_key in list(attribute_dict[packet_num][key]):
                    extracted_val = extract_substring(inner_key, '.')
                    new_dict_name = inner_key.replace(extracted_val, f'{key}')
                    combine_dict[packet_num][key][new_dict_name] = combine_dict[packet_num][key].pop(inner_key)
    return attribute_dict


def only_grab_specific_attributes(attribute_dict: dict, search_for_iterable: list|tuple|set) -> dict:
    subset_dict = dict()
    for index, (packet_data) in enumerate(attribute_dict.values(), start=1):
        new_packet_num = f'Packet {index}'
        subset_dict[new_packet_num] = {}
        for layer_name, layer_value in packet_data.items():
            if layer_value is not None:
                filtered_values = {key: value for key, value in layer_value.items() if key in search_for_iterable}
                if filtered_values:
                    subset_dict[new_packet_num][layer_name] = filtered_values
    return subset_dict


live_traffic = capture_live_traffic(interface_to_use='Ethernet 2', num_packets=100)

osi_layers = instantiate_osi_layers(physical_layer=PhysicalLayer(), datalink_layer=DataLinkLayer(), network_layer=NetworkLayer(), transport_layer=TransportLayer(), session_layer=SessionLayer(), presentation_layer=PresentationLayer(), application_layer=ApplicationLayer())

layer_info = {layer_name: get_layer_info(layer, live_traffic) for layer_name, layer in osi_layers.items()}

layer_attributes = {layer_name: get_layer_attributes(layer, layer.get_packet_layer()) for layer_name, layer in layer_info.items()}

combine_dict = {}
for i in range(len(live_traffic)):
    packet_key_name = f'Packet {i + 1}'
    combine_dict[packet_key_name] = {}
    for name in layer_attributes:
        update_combine_dict(combine_dict, packet_key_name, name, layer_attributes[name])

combine_dict = format_attribute_dict(combine_dict)
list_of_attributes_to_add = ['datalink_layer.src', 'datalink_layer.dst', 'network_layer.src', 'network_layer.dst', 'transport_layer.srcport', 'transport_layer.dstport']
combine_dict = only_grab_specific_attributes(combine_dict, list_of_attributes_to_add)
# pprint(testing)
# pprint(combine_dict)
