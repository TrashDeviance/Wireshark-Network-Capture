import sqlite3
from capture_traffic import combine_dict
from capture_traffic import list_of_attributes_to_add
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

# Mapping attributes to index values to guarantee correct placing before sent to SQL DB
mapping_attributes_order = dict()
for index, element in enumerate(list_of_attributes_to_add):
    mapping_attributes_order[element] = index

# Finding attributes values and then store them into a list to be sent to DB
for index, value in enumerate(combine_dict.values(), start=1):
    values_to_add_list = list([None] * len(attributes))
    for keys, values in value.items():
        for inner_key, inner_value in values.items():
            if inner_key in mapping_attributes_order:
                values_to_add_list[mapping_attributes_order[inner_key]] = inner_value

    print(values_to_add_list)
    create_packet_info_table.execute(f"""INSERT INTO packet_info ({attributes_to_insert_into_table}) VALUES ({parameterized_query(attributes)})""", (values_to_add_list))

    connection.commit()

rows = create_packet_info_table.execute('SELECT * FROM packet_info').fetchall()
for packet_info in rows:
    print(packet_info)

connection.close()