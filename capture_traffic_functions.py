import pyshark


def live_capture(interface: str, num_packets: int, **kwargs) -> pyshark.LiveCapture:
    '''
    Creates a `live` traffic capturing instance that captures traffic over a specific interface.

    Parameters:
    - `interface` (str): An interface that will be used to capture packets from. Exp: `Ethernet 2`.
    - `num_packets` (int): specifying the number of packets to capture from the interface.
    - `**kwargs`: Additional keyword arguments passed to `pyshark.LiveCapture`.

    Returns:
    - `pyshark.LiveCapture`: An object that represents the live capture interface. Stores the packets from the traffic. 
    '''
    capture = pyshark.LiveCapture(interface=interface, **kwargs)
    capture.sniff(packet_count=num_packets)
    return capture


def remote_capture(remote_host: str, remote_interface: str, num_packets: int, **kwargs) -> pyshark.RemoteCapture:
    '''
    Creates a `remote` traffic capturing instance that captures traffic over a specific interface.

    Parameters:
    - `remote_host` (str): A remote host to capture traffic from.
    - `remote_interface` (str): An interface that will be used to capture packets from. Exp: `Ethernet 2`.
    - `num_packets` (int): specifying the number of packets to capture from the interface.
    - `**kwargs`: Additional keyword arguments passed to `pyshark.RemoteCapture`.

    Returns:
    - `pyshark.RemoteCapture`: An object that represents the remote capture interface. Stores the packets from the traffic. 
    '''
    capture = pyshark.RemoteCapture(remote_host=remote_host, remote_interface=remote_interface, **kwargs)
    capture.sniff(packet_count=num_packets)
    return capture


def file_capture(file_path: str, num_packets: int, **kwargs) -> pyshark.FileCapture:
    '''
    Creates a `file` traffic capturing instance that captures traffic over a specific interface.

    Parameters:
    - `file_path` (str): A file path that will be used to capture traffic from.
    - `num_packets` (int): specifying the number of packets to capture from the interface.
    - `**kwargs`: Additional keyword arguments passed to `pyshark.FileCapture`.

    Returns:
    - `pyshark.FileCapture`: An object that represents the file capture interface. Stores the packets from the traffic. 
    '''
    capture = pyshark.FileCapture(input_file=file_path, **kwargs)
    capture.sniff(packet_count=num_packets)
    return capture


def in_memory_capture(num_packets: int, **kwargs) -> pyshark.InMemCapture:
    '''
    Creates a `in memory` traffic capturing instance that captures traffic over a specific interface.

    Parameters:
    - `num_packets` (int): specifying the number of packets to capture from the interface.
    - `**kwargs`: Additional keyword arguments passed to `pyshark.InMemCapture`.

    Returns:
    - `pyshark.InMemCapture`: An object that represents the memory capture interface. Stores the packets from the traffic. 
    '''
    capture = pyshark.InMemCapture(**kwargs)
    capture.sniff(packet_count=num_packets)
    return capture


def live_ring_capture(interface: str, num_packets: int, **kwargs) -> pyshark.LiveRingCapture:
    '''
    Creates a `live ring` traffic capturing instance that captures traffic over a specific interface.

    Parameters:
    - `interface` (str): An interface that will be used to capture packets from. Exp: `Ethernet 2`.
    - `num_packets` (int): specifying the number of packets to capture from the interface.
    - `**kwargs`: Additional keyword arguments passed to `pyshark.LiveRingCapture`.

    Returns:
    - `pyshark.LiveRingCapture`: An object that represents the live ring capture interface. Stores the packets from the traffic. 
    '''
    capture = pyshark.LiveRingCapture(interface=interface, **kwargs)
    capture.sniff(packet_count=num_packets)
    return capture


def instantiate_osi_layers(**kwargs) -> dict:
    '''
    Instantiates a custom number of objects from different `OSI` layers.

    Parameters:
    - `**kwargs`: Specify which layers from the OSI model to instantiate objects from.

    Returns:
    - `dict`: A dictionary that stores the `key` - object name with its `value` object reference.

    Example:
    - `instantiate_osi_layers(physical_layer=PhysicalLayer(), datalink_layer=DataLinkLayer()...)`
    '''
    return kwargs


def get_layer_info(layer, capture_interface) -> dict:
    '''
    Retrieves the layer info for each `OSI` layer that has been instantied from the `instantiate_osi_layers()`.

    Parameters:
    - `layer` (packet_classes.layer): Value reference that is stored in the Dictionary from the `instantiate_osi_layers()`.
    - `capture_interface`: This is the interface that is being used to retrieve packets from.

    Returns:
    - `dict`: Contains the layer name as the `key` and the packet_classes object that contains the layers for each packet stored as the `value`.
    '''
    return layer.get_complete_layer_info(capture_interface)


def get_layer_attributes(info, layer_list) -> dict:
    '''
    Retrieves the attributes from each layer object that is stored in the dict from the `get_layer_info()`.

    Parameters:
    - `info` (packet_classes.layer): Value reference that is stored in the dict from the `get_layer_info()`.
    - `layer_list` (list): Contains a list of layers to obtain the attributes from.

    Returns:
    - `dict`: Contains the layer name as the `key` and all of the layer attriubtes stored as the `value`.
    '''
    return info.get_attribute_from_layer(layer_list)


def reformat_attributes_dict(attributes_dict, packet_key_name, layer_name, attributes) -> dict:
    '''
    Reformats the structure of the dict that is returned from the `get_layer_attributes()`.

    Parameters:
    - `attributes_dict` (dict): The dict where the strucure will be changed.
    - `packet_key_name` (str): The key name of the packet that will need to be looked into. Exp key name: `'Packet 1'`.
    - `layer_name` (str): The nested key name stored within the packet where the attributes are stored. Exp key name: `'datalink_layer'`
    - `attributes` (dict): This is the values section where the packet contents are stored.

    Returns:
    - `dict`: An updated version of the dict that came from the `get_layer_attributes()`.

    Example:
    - Structure of the dict will now be `attributes_dict['Packet 1']['datalink_layer']`.
    '''
    try:
        attributes_dict[packet_key_name].update({layer_name: attributes[packet_key_name]})
    except KeyError:
        attributes_dict[packet_key_name].update({layer_name: None})


def extract_substring(iterable: list | dict | tuple | set, identifier: str) -> str:
    '''
    Used in the `format_attribute_dict()` to allow the ability to only return specific content from the attribute_dict instead of returning every layers information.

    Parameters:
    - iterable: An iterable object to iterate over to retrieve characters from.
    - identifier (str): Specify an identifier that the iterable should stop at.

    Returns:
    - A sub_string from the iterable. This will allow the ability to choose when an interable should stop at a specific character.
    '''
    new_substring = str()
    for char in iterable:
        if char != identifier:
            new_substring += char
        else:
            break
    return new_substring


def modify_keys_attribute_dict(attribute_dict: dict) -> dict:
    """
    Modifes the inner keys in the dictionary that displays various content like src_ip, dest_ip, src_mac, etc.
    
    Parameters:
    - `attribute_dict` (dict): The dict that contains the attributes values for each layer.

    Returns:
    - A new dict where the key names are more precise.
    """
    for index in range(len(attribute_dict)):
        packet_num = f'Packet {index + 1}'
        for key, value in attribute_dict[packet_num].items():
            if value != None:
                for inner_key in list(attribute_dict[packet_num][key]):
                    extracted_val = extract_substring(inner_key, '.')
                    new_dict_name = inner_key.replace(extracted_val, f'{key}')
                    attribute_dict[packet_num][key][new_dict_name] = attribute_dict[packet_num][key].pop(inner_key)
    return attribute_dict


def only_grab_specific_attributes(attribute_dict: dict, search_for_iterable: list|tuple|set) -> dict:
    """
    Allows the functionality to choose specific attributes from the dict instead of all of them.

    Parameters:
    - `attribute_dict` (dict): The dict that contains the attribute values.
    - `search_for_iterable`: An interable that contains the attribute values from the dict to only grab from.

    Returns:
    - A dict that contains the subset values of the original dict.
    """
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
