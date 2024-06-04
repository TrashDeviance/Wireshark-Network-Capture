from abc import ABC, abstractmethod
from typing import Optional, Union
import pyshark


def retrieve_packet(capture_interface: Union[pyshark.RemoteCapture, pyshark.FileCapture, pyshark.InMemCapture, pyshark.LiveCapture, pyshark.LiveRingCapture]) -> dict:
    """
    Implements retrieval of packets from a capture interface and organizes the packets into a nested dictionary. The data is organized by packet number, layer, and then contents of the layer. Can be used in classes where you want to manipulate the packet data.
    
    Parameters:
    - capture_interface: an object created from one of the following pyshark classes.

    Returns:
    - dict: A dictionary that stores each packet alongside its following layers
    """
    packet_dict = {}
    for i, packet in enumerate(capture_interface):
        packet_key_name = f'Packet {i + 1}'
        packet_dict[packet_key_name] = {}
        for layer in packet:
            packet_dict[packet_key_name][f'{layer.layer_name}'] = layer
    return packet_dict


def retrieve_packet_layer(layer_list: list[str], packet_dict: dict) -> list:
    """Implements retrieval of a layer from packet data stored in a dictionary.
        Returns:
            List: A list containing values from the specified layer."""
    list_of_eths = []
    for packet in packet_dict:
        for layer in packet_dict[packet]:
            if layer in layer_list:
                list_of_eths.append(packet_dict[packet][layer])
    return list_of_eths


def retrieve_attribute_from_layer(layers: list[pyshark.packet.layers.xml_layer.XmlLayer], attributes_of_layer: Optional[list[str]] = None) -> dict:
    layer_dict = {}
    if attributes_of_layer == None:
        for i, layer in enumerate(layers):
            packet_key_name = f'Packet {i + 1}'
            layer_dict[packet_key_name] = layer._all_fields
        return layer_dict
            
    for i, layer in enumerate(layers):
        packet_key_name = f'Packet {i + 1}'
        layer_dict[packet_key_name] = {}
        for attribute in attributes_of_layer:
            retrieve_attribute_val = layer.get(attribute, None)
            if attribute not in layer_dict:
                layer_dict[packet_key_name].update({attribute: retrieve_attribute_val})
    return layer_dict


# Interface template used to create sub classes for different OSI model layers
class PacketInterface(ABC):
    
    @abstractmethod
    def get_packet_layer(self) -> list:
       """
        Template method to retrieve a specific layer from a packet data stored in a dictionary..
        Returns:
            List: A list of layer data extracted from the packet.
        """

    @abstractmethod
    def get_attribute_from_layer(self, layers: list[pyshark.packet.layers.xml_layer.XmlLayer], attributes_of_layer: Optional[list[str]] = None) -> dict:
       """
        Template method to specified attributes from a list of network layer objects or all attributes if none are specified.
        Returns:
            Dict: A dictionary of attributes for a specified layer.

        Parameters:
        - layers (List[XmlLayer]): A list of XmlLayer objects from which attributes are to be retrieved. This list is typically obtained from the `get_packet_layer()` method.
        - attributes_of_layer (Optional[List[str]]): A list of strings specifying the names of the attributes to retrieve from each layer. If not provided, all attributes are returned.

        Returns:
        - dict: A dictionary where each key is 'Packet {index}', corresponding to each layer in the input list, and the value is another dictionary of requested attributes and their values for that layer. If no attributes are specified, all attributes of each layer are included.

        Example:
        - If attributes_of_layer is ['src', 'dst'], the output might be {'Packet 1': {'src': '192.168.1.1', 'dst': '192.168.1.2'}, ...}

        Note:
        - All fields names for the layer object can be accessed by calling the layer object with the attribute field_names. object.field_names.
        """
       

# Indiviual OSI layers
class OSIPhysicalLayer(PacketInterface):
    def __init__(self, capture_interface: Union[pyshark.RemoteCapture, pyshark.FileCapture, pyshark.InMemCapture, pyshark.LiveCapture, pyshark.LiveRingCapture]) -> None:
        self.capture_interface = capture_interface
        self.packet_dict = retrieve_packet(self.capture_interface)
        self.list_of_layers = retrieve_packet_layer([None], self.packet_dict)

    
    def get_packet_layer(self) -> list:
        return self.list_of_layers

    
    def get_attribute_from_layer(self, layers: list[pyshark.packet.layers.xml_layer.XmlLayer], attributes_of_layer: Optional[list[str]] = None) -> dict:
        return retrieve_attribute_from_layer(layers, attributes_of_layer)


class OSIDataLinkLayer(PacketInterface):
    def __init__(self, capture_interface: Union[pyshark.RemoteCapture, pyshark.FileCapture, pyshark.InMemCapture, pyshark.LiveCapture, pyshark.LiveRingCapture]) -> None:
        self.capture_interface = capture_interface
        self.packet_dict = retrieve_packet(self.capture_interface)
        self.list_of_layers = retrieve_packet_layer(['eth', 'arp', 'rarp', 'cslip', 'ppp', 'ppp-mp', 'slip'], self.packet_dict)


    def get_packet_layer(self) -> list:
        return self.list_of_layers

    
    def get_attribute_from_layer(self, layers: list[pyshark.packet.layers.xml_layer.XmlLayer], attributes_of_layer: Optional[list[str]] = None) -> dict:
        return retrieve_attribute_from_layer(layers, attributes_of_layer)


class OSINetworkLayer(PacketInterface):
    def __init__(self, capture_interface: Union[pyshark.RemoteCapture, pyshark.FileCapture, pyshark.InMemCapture, pyshark.LiveCapture, pyshark.LiveRingCapture]) -> None:
        self.capture_interface = capture_interface
        self.packet_dict = retrieve_packet(self.capture_interface)
        self.list_of_layers = retrieve_packet_layer(['ip', 'ipv6', 'icmp', 'icmpv6', 'igmp', 'bgp', 'egp', 'ggp', 'igrp', 'nd', 'ospf', 'rip', 'ripng', 'dsr', 'ah', 'esp'], self.packet_dict)

    
    def get_packet_layer(self) -> list:
       return self.list_of_layers

    
    def get_attribute_from_layer(self, layers: list[pyshark.packet.layers.xml_layer.XmlLayer], attributes_of_layer: Optional[list[str]] = None) -> dict:
        return retrieve_attribute_from_layer(layers, attributes_of_layer)


class OSITransportLayer(PacketInterface):
    def __init__(self, capture_interface: Union[pyshark.RemoteCapture, pyshark.FileCapture, pyshark.InMemCapture, pyshark.LiveCapture, pyshark.LiveRingCapture]) -> None:
        self.capture_interface = capture_interface
        self.packet_dict = retrieve_packet(self.capture_interface)
        self.list_of_layers = retrieve_packet_layer(['dccp', 'sctp', 'udp', 'udp-lite', 'tcp', 'rtp', 'rtcp'], self.packet_dict)

    
    def get_packet_layer(self) -> list:
       return self.list_of_layers

    
    def get_attribute_from_layer(self, layers: list[pyshark.packet.layers.xml_layer.XmlLayer], attributes_of_layer: Optional[list[str]] = None) -> dict:
        return retrieve_attribute_from_layer(layers, attributes_of_layer)


class OSISessionLayer(PacketInterface):
    def __init__(self, capture_interface: Union[pyshark.RemoteCapture, pyshark.FileCapture, pyshark.InMemCapture, pyshark.LiveCapture, pyshark.LiveRingCapture]) -> None:
        self.capture_interface = capture_interface
        self.packet_dict = retrieve_packet(self.capture_interface)
        self.list_of_layers = retrieve_packet_layer(['netbios', 'netdump', 'onc-rpc', 'dce', 'rpc', 'dce/rpc', 'http', 'smtp'], self.packet_dict)
    
    def get_packet_layer(self) -> list:
       return self.list_of_layers

    
    def get_attribute_from_layer(self, layers: list[pyshark.packet.layers.xml_layer.XmlLayer], attributes_of_layer: Optional[list[str]] = None) -> dict:
        return retrieve_attribute_from_layer(layers, attributes_of_layer)


class OSIPresentationLayer(PacketInterface):
    def __init__(self, capture_interface: Union[pyshark.RemoteCapture, pyshark.FileCapture, pyshark.InMemCapture, pyshark.LiveCapture, pyshark.LiveRingCapture]) -> None:
        self.capture_interface = capture_interface
        self.packet_dict = retrieve_packet(self.capture_interface)
        self.list_of_layers = retrieve_packet_layer(['mime'], self.packet_dict)
    
    def get_packet_layer(self) -> list:
       return self.list_of_layers

    
    def get_attribute_from_layer(self, layers: list[pyshark.packet.layers.xml_layer.XmlLayer], attributes_of_layer: Optional[list[str]] = None) -> dict:
        return retrieve_attribute_from_layer(layers, attributes_of_layer)


class OSIApplicationLayer(PacketInterface):
    def __init__(self, capture_interface: Union[pyshark.RemoteCapture, pyshark.FileCapture, pyshark.InMemCapture, pyshark.LiveCapture, pyshark.LiveRingCapture]) -> None:
        self.capture_interface = capture_interface
        self.packet_dict = retrieve_packet(self.capture_interface)
        self.list_of_layers = retrieve_packet_layer(['ancp', 'bootp', 'dhcp', 'dns', 'ftp', 'imap', 'iwarp-ddp', 'iwarp-mpa', 'iwarp-rdmap', 'iwarp', 'nntp', 'ntp', 'pana', 'pop', 'radius', 'rlogin', 'rsh', 'rsip', 'ssh', 'snmp', 'telnet', 'tftp', 'sasp', 'data'], self.packet_dict)
    
    def get_packet_layer(self) -> list:
       return self.list_of_layers

    
    def get_attribute_from_layer(self, layers: list[pyshark.packet.layers.xml_layer.XmlLayer], attributes_of_layer: Optional[list[str]] = None) -> dict:
        return retrieve_attribute_from_layer(layers, attributes_of_layer)


# Main factory class
class PacketFactory(ABC):
    """Factroy class that will be used to create concrete factories for different layers of a packet.
       
       Returns:
       - An instance of the `PacketInterface` class which is used when creating many different layers from a packet.

       Example:
       - Creating a concrete factory that inherits from this `PacketFactory` class will be used to return different classes that are made to return various information from different layers like `eth`, `ip` etc.
    """
    @abstractmethod
    def get_complete_layer_info(self) -> PacketInterface:
        """This method will be called on a concrete factory to return the properties of layer from the `PacketInterface` class. 
        
        Returns:
        - An instance of `PacketInterface` class which will then return an instance of a layer class.

        Example:
        - Creating a class like `EthernetPacket` which will inherit from the `PacketFactory` class. Since the `get_complete_layer_info` method will return an instance of `PacketInterface` which has its own subclasses like `EthernetLayer`. 
        A return statement can then be used to return one of these subclasses.
        - return `EthernetLayer()`
        """


#Concrete factory creations from PacketFactory
class PhysicalLayer(PacketFactory):
    """
    Concrete subclass factory inheriting from the `PacketFactory` main class. 
    
    Return:
    - OSIPhysicalLayer: Represents information that would be stored for this layer in the OSI model (Open Systems Interconnection).
    """
    
    def get_complete_layer_info(self, cap_interface_value) -> PacketInterface:
        return OSIPhysicalLayer(capture_interface=cap_interface_value)


class DataLinkLayer(PacketFactory):
    """
    Concrete subclass factory inheriting from the `PacketFactory` main class. 
    
    Return:
    - OSIDataLinkLayer: Represents information that would be stored for this layer in the OSI model (Open Systems Interconnection).
    """
    
    def get_complete_layer_info(self, cap_interface_value) -> PacketInterface:
        return OSIDataLinkLayer(capture_interface=cap_interface_value)


class NetworkLayer(PacketFactory):
    """
    Concrete subclass factory inheriting from the `PacketFactory` main class. 
    
    Return:
    - OSINetworkLayer: Represents information that would be stored for this layer in the OSI model (Open Systems Interconnection).
    """
    def get_complete_layer_info(self, cap_interface_value) -> PacketInterface:
        return OSINetworkLayer(capture_interface=cap_interface_value)
    

class TransportLayer(PacketFactory):
    """
    Concrete subclass factory inheriting from the `PacketFactory` main class. 
    
    Return:
    - OSITransportLayer: Represents information that would be stored for this layer in the OSI model (Open Systems Interconnection).
    """
    
    def get_complete_layer_info(self, cap_interface_value) -> PacketInterface:
        return OSITransportLayer(capture_interface=cap_interface_value)


class SessionLayer(PacketFactory):
    """
    Concrete subclass factory inheriting from the `PacketFactory` main class. 
    
    Return:
    - OSISessionLayer: Represents information that would be stored for this layer in the OSI model (Open Systems Interconnection).
    """
    
    def get_complete_layer_info(self, cap_interface_value) -> PacketInterface:
        return OSISessionLayer(capture_interface=cap_interface_value)


class PresentationLayer(PacketFactory):
    """
    Concrete subclass factory inheriting from the `PacketFactory` main class. 
    
    Return:
    - OSIPresentationLayer: Represents information that would be stored for this layer in the OSI model (Open Systems Interconnection).
    """
    
    def get_complete_layer_info(self, cap_interface_value) -> PacketInterface:
        return OSIPresentationLayer(capture_interface=cap_interface_value)


class ApplicationLayer(PacketFactory):

    """
    Concrete subclass factory inheriting from the `PacketFactory` main class. 
    
    Return:
    - OSIApplicationLayer: Represents information that would be stored for this layer in the OSI model (Open Systems Interconnection).
    """
    
    def get_complete_layer_info(self, cap_interface_value) -> PacketInterface:
        return OSIApplicationLayer(capture_interface=cap_interface_value)
