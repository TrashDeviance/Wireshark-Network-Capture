import pyshark
from packet_classes import PhysicalLayer, DataLinkLayer, NetworkLayer, TransportLayer, SessionLayer, PresentationLayer, ApplicationLayer 
from pprint import pprint

capture_live_traffic = pyshark.LiveCapture(interface='Ethernet 2')
capture_live_traffic.sniff(packet_count=10)

# Below are a few examples on how to access specific information from different layers within packets
'''
# Print out the contents of each packet
for packet in capture_live_traffic:
    print(packet)

# Iterate through each layer per packet and display all of the layers and the fields related to the layers that can be used as attributes
for packet in capture_live_traffic:
    for layer in packet:
        print(f'Layer: {layer.layer_name}')
        print(f'Layer Fields: {layer.field_names}')

# Looks for a specific layer that is eth and prints out the field names for this layer. Prints out the src and dest mac for this layer wtihin the packet
for packet in capture_live_traffic:
    for layer in packet:
        if layer.layer_name == 'eth':
            # print(layer.field_names)
            print(f'Src Mac: {packet.eth.src}, Dest Mac: {packet.eth.dst}')
'''
