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


live_traffic = capture_live_traffic(interface_to_use='Ethernet 2', num_packets=2)

osi_layers = instantiate_osi_layers(physical_layer=PhysicalLayer(), datalink_layer=DataLinkLayer(), network_layer=NetworkLayer(), transport_layer=TransportLayer(), session_layer=SessionLayer(), presentation_layer=PresentationLayer(), application_layer=ApplicationLayer())

layer_info = {layer_name: get_layer_info(layer, live_traffic) for layer_name, layer in osi_layers.items()}

layer_attributes = {layer_name: get_layer_attributes(layer, layer.get_packet_layer()) for layer_name, layer in layer_info.items()}

combine_dict = {}
for i in range(len(live_traffic)):
    packet_key_name = f'Packet {i + 1}'
    combine_dict[packet_key_name] = {}
    for name in layer_attributes:
        update_combine_dict(combine_dict, packet_key_name, name, layer_attributes[name])