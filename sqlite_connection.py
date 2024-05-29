import sqlite3
from capture_traffic import combine_dict
from pprint import pprint

def create_connection_to_db(schema: str) -> sqlite3.Connection:
    """
    This function is used to create a connection to a database.

    Parameters:
    - `schema`: (str): The name of the database schema to be created if it is not already present.

    Returns:
    - `Connection`: Will return a connection that can be used to create/modify tables.
    """
    return sqlite3.connect(schema)


def create_table_for_db(connection: sqlite3.Connection, sql_query: str) -> None:
    generate_table = connection.cursor()
    return generate_table.execute(sql_query)


def format_attribute_columns_for_table(attributes: dict | list) -> str:
    if type(attributes) == dict:
        return ',\n'.join([f'{key} {value}' for key, value in attributes.items()])
    
    elif type(attributes) == list:
        return ',\n'.join([attr for attr in attributes])
    

def parameterized_query(num_of_inputs: int | list |dict | tuple) -> str:
    if type(num_of_inputs) == int:
        return ','.join(['?' for _ in range(num_of_inputs)])
    
    else:
        return ','.join(['?' for _ in range(len(num_of_inputs))])


# Create a db scheme connection, specify attributes to use for the packet_info table, and create the table
connection = create_connection_to_db('packet_storage.db')

attributes = {'src_mac': 'TEXT', 
              'dest_mac': 'TEXT', 
              'src_ip': 'TEXT', 
              'dest_ip': 'TEXT', 
              'src_port': 'INT', 
              'dest_port': 'INT'
              }

attributes_to_create_table = format_attribute_columns_for_table(attributes)

create_packet_info_table = create_table_for_db(connection, f"""CREATE TABLE IF NOT EXISTS packet_info (Packet_ID INTEGER PRIMARY KEY, {attributes_to_create_table})""")

attributes_to_insert_into_table = format_attribute_columns_for_table(list(attributes.keys()))


retrieve_packet_keys = combine_dict.keys()

keys_to_search_for = tuple(("eth.src", "eth.dst", ".src_host", ".dst_host", ".srcport", ".dstport"))

# Iterate over each packet key, exp 'Packet 1'
for packet in retrieve_packet_keys:
    values_to_insert_into_table = []
    
    # retrieving the layer name with the values store in the layer dict
    for key, value in combine_dict[packet].items():
        # Checks to see if the layer contains any values in the dict
        if combine_dict[packet][key] != None:
            # retrieving the keys inside of the layer
            for inner_key in combine_dict[packet][key].keys():
                # filtering down the keys we want to store in packet_info table
                if inner_key.endswith(keys_to_search_for):
                    values_to_insert_into_table.append(combine_dict[packet][key][inner_key])
                    
    
    # extends the list to match the length of the attributes the table will have
    current_len = len(values_to_insert_into_table)
    if current_len != len(attributes):
        amount = len(attributes) - current_len
        values_to_insert_into_table.extend([None] * amount)
    
    complete_values_to_add = tuple(values_to_insert_into_table)
    # print(complete_values_to_add)
    create_packet_info_table.execute(f"""INSERT INTO packet_info ({attributes_to_insert_into_table}) VALUES ({parameterized_query(attributes)})""", (complete_values_to_add))

# connection.commit()

# rows = create_packet_info_table.execute('SELECT * FROM packet_info').fetchall()
# for packet_info in rows:
#     print(packet_info)

# connection.close()