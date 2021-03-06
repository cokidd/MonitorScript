  
#!/usr/bin/python
# -*- coding: UTF-8 -*-

import argparse,struct


def init_data(pid):
	pid_file = '/tmp/hsperfdata_root/'+pid
        with open(pid_file, 'rb') as f:
                data = f.read()
                return memoryview(data)

def header_check(data):
	magic = struct.unpack('I', data[0:4])[0]
	if magic != 3233873610:
                print("Bad Magic: %#x"%magic)


def process_other_key(data, key, start_offset, numentries):
	for index in range(0, numentries):
		entry = struct.unpack('3I4cI', data[start_offset:start_offset+20])
		entry_length, name_offset, vector_length, data_type, flags, data_unit, data_var, data_offset = entry
		name_start = start_offset + name_offset
		name_size = len(key)
		key_name = data[name_start:name_start+name_size]
		if key_name == key:
			data_start = start_offset+data_offset
			key_data = struct.unpack('L', data[data_start:data_start+8])[0]
			return key_data
		start_offset += entry_length

		


def process_perfdata(pid, key):
	data = init_data(pid)
	header_check(data)
	entry_offset = struct.unpack('I', data[24:28])[0]
	numentries = struct.unpack('I', data[28:32])[0]
	if key == 'sun.perfdata.used':
		print(struct.unpack('I', data[8:12])[0])
	elif key == 'sun.perfdata.overflow':
		print(struct.unpack('I', data[12:16])[0])
	elif key == 'sun.perfdata.timestamp':
		print(struct.unpack('L', data[16:24])[0])
	elif key == 'YGCT':
		print(process_other_key(data, "sun.gc.collector.0.invocations", entry_offset, numentries)/float(process_other_key(data, "sun.os.hrt.frequency", entry_offset, numentries)))
	elif key == 'YGC':
		print(process_other_key(data, "sun.gc.collector.0.invocations", entry_offset, numentries))
	elif key == 'FGCT':
		print(process_other_key(data, "sun.gc.collector.1.time", entry_offset, numentries)/float(process_other_key(data, "sun.os.hrt.frequency", entry_offset, numentries)))
	elif key == 'FGC':
		print(process_other_key(data, "sun.gc.collector.1.invocations", entry_offset, numentries))
	elif key == 'OU':
		print(process_other_key(data, "sun.gc.generation.1.space.0.used", entry_offset, numentries))
	elif key == 'OC':
		print(process_other_key(data, "sun.gc.generation.1.space.0.capacity", entry_offset, numentries))
	elif key == 'MU':
		print(process_other_key(data, "sun.gc.metaspace.used", entry_offset, numentries))
	elif key == 'MC':
		print(process_other_key(data, "sun.gc.metaspace.capacity", entry_offset, numentries))
	else:
		key_data=process_other_key(data, key, entry_offset, numentries)
		print(key_data)


def process_argparse():
	parser = argparse.ArgumentParser(description="JVM Perfdata Monitor by Python")
	parser.add_argument("-k","--key", dest='key', help="Monitor java parameter.")
	parser.add_argument("-p","--pid", dest='pid', help="Need to monitor java pid by root.")
	args = parser.parse_args()
	process_perfdata(args.pid, args.key)
	
	
if __name__ == "__main__":
	process_argparse()
