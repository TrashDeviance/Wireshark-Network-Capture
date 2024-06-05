from capture_traffic_functions import live_capture, instantiate_osi_layers, get_layer_info, get_layer_attributes, reformat_attributes_dict, modify_keys_attribute_dict, only_grab_specific_attributes
from packet_classes import PhysicalLayer, DataLinkLayer, NetworkLayer, TransportLayer, SessionLayer, PresentationLayer, ApplicationLayer
from pprint import pprint


live_traffic = live_capture(interface='Ethernet 2', num_packets=2, encryption_type='wpa-pwk')

osi_layers = instantiate_osi_layers(physical_layer=PhysicalLayer(), datalink_layer=DataLinkLayer(), network_layer=NetworkLayer(), transport_layer=TransportLayer(), session_layer=SessionLayer(), presentation_layer=PresentationLayer(), application_layer=ApplicationLayer())

layer_info = {layer_name: get_layer_info(layer, live_traffic) for layer_name, layer in osi_layers.items()}

layer_attributes = {layer_name: get_layer_attributes(layer, layer.get_packet_layer()) for layer_name, layer in layer_info.items()}

combine_dict = {}
for i in range(len(live_traffic)):
    packet_key_name = f'Packet {i + 1}'
    combine_dict[packet_key_name] = {}
    for name in layer_attributes:
        reformat_attributes_dict(combine_dict, packet_key_name, name, layer_attributes[name])

combine_dict = modify_keys_attribute_dict(combine_dict)

list_of_attributes_to_add = ['datalink_layer.src', 'datalink_layer.dst', 'network_layer.src', 'network_layer.dst', 'transport_layer.srcport', 'transport_layer.dstport']
combine_dict = only_grab_specific_attributes(combine_dict, list_of_attributes_to_add)
# pprint(testing)
# pprint(combine_dict)