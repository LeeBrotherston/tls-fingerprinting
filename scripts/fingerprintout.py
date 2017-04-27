#!/usr/bin/env python


# XXX Recalculate the sizes for int's instead of char arrays
# XXX Work out how to pre-populate as ints instead of char arrays

import argparse
import json
import sys
import re
import binascii			# Needed for the binary option

# Open the JSON file
def read_file(filename):
	jfile = []
	with open(filename) as f:
		for line in f:
			jfile.append(json.loads(line))
	return jfile

# Take Single or multi byte strings or mixed: "0x00 0x0000 0x00"
# and return entirely single byte version: "0x00 0x00 0x00 0x00" in binary format
def byte_to_bin(in_string):
	in_string = in_string.replace(' ', '')
	in_string = in_string.replace('0x', '')
	out_string = binascii.a2b_hex(in_string)
  	return out_string


def cleanse(filename):
	# Reoutput the database cleaned a little...  e.g. before uploading somewhere
	jfile = read_file(filename)
	objcount = len(jfile)
	j2file = []
	with open(filename) as f:
		for line in f:
			j2file.append(json.loads(line))
	# Not the smartest check ever but if the fingerprint is the same, not including
	# id, desc & server it'll flag as a duplicate.  Will miss a 100% identical line,
	# but that's ok because this was for the stuff sort & unique can't handle.
	for i in jfile:
		for x in j2file:
			if i["record_tls_version"].strip() == x["record_tls_version"].strip() and \
				i["tls_version"].strip() == x["tls_version"].strip() and \
				i["ciphersuite_length"].strip() == x["ciphersuite_length"].strip() and \
				i["ciphersuite"].strip() == x["ciphersuite"].strip() and \
				i["compression_length"].strip() == x["compression_length"].strip() and \
				i["compression"].strip() == x["compression"].strip() and \
				i["extensions"].strip() == x["extensions"].strip() and	\
				"e_curves" in i and \
				"e_curves" in x \
				and	i["e_curves"].strip() == x["e_curves"].strip() and \
				"sig_alg" in i and \
				"sig_alg" in x and \
				i["sig_alg"].strip() == x["sig_alg"].strip() and \
				"ec_point_fmt" in i and \
				i["ec_point_fmt"].strip() == x["ec_point_fmt"].strip():
					if i["desc"].strip() != x["desc"].strip():
						print "# Oh no, 2 signatures match: "+str(i["desc"].strip())+" - "+str(x["desc"].strip())
					#else:
						#print "# Oh no, duplicate copies of: "+str(i["desc"])

		# Fix some minor annoyances
		# I hate commas in quotes in a comma delimited file... I like cut... OK?
		i["desc"] = i["desc"].replace(",", " ")

		# XXX Need to get rid of extra spaces
		# XXX Cleanup database if field found that is just spaces

		# Reprint, hopefully with nicely equally spaced and comma'd and whatever fields
		print "{\"id\": "+str(i["id"])+", \"desc\": \""+i["desc"].strip()+"\", ",
		print "\"record_tls_version\": \""+i["record_tls_version"].strip()+"\", \"tls_version\": \""+i["tls_version"].strip()+"\", ",
		print "\"ciphersuite_length\": \""+i["ciphersuite_length"].strip()+"\", ",
		print "\"ciphersuite\": \""+i["ciphersuite"].strip()+"\", ",
		print "\"compression_length\": \""+i["compression_length"].strip()+"\", ",
		print "\"compression\": \""+i["compression"].strip()+"\", ",
		print "\"extensions\": \""+i["extensions"].strip()+"\"",
		if "e_curves" in i:
			if len(i["e_curves"].strip()) > 0:
				print ", \"e_curves\": \""+i["e_curves"].strip()+"\"",
		if "sig_alg" in i:
			if len(i["sig_alg"].strip()) > 0:
				print ", \"sig_alg\": \""+i["sig_alg"].strip()+"\"",
		if "ec_point_fmt" in i:
			if len(i["ec_point_fmt"].strip()) > 0:
				print ", \"ec_point_fmt\": \""+i["ec_point_fmt"].strip()+"\"",
		print "}"


def ids(filename, initial=False):
	# Creating Snort signatures from the fingerprint data
	# Walk through each entry outputting the appropriate snort rule
	jfile = read_file(filename)
	sid = 1000000
	for i in jfile:

		# Reformat some of the values prior to printing out rules
		# Different format in the JSON to how suricata/snort want it
		# Mostly just removing 0x and changing how bytes are grouped
		i["desc"] = i["desc"].replace(";", ":")
		i["record_tls_version"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'\1 \2', i["record_tls_version"])
		i["tls_version"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'\1 \2', i["tls_version"])
		i["ciphersuite_length"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'\1 \2', i["ciphersuite_length"])
		i["ciphersuite"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'\1 \2', i["ciphersuite"])
		i["compression_length"] = re.sub(r'0x([0-9A-Fa-f]{1,2})', r'\1', hex(int(i["compression_length"])))
		i["compression_length"] = re.sub(r'^([0-9A-Fa-f])$', r'0\1', i["compression_length"])
		i["compression"] = re.sub(r'0x([0-9A-Fa-f]{2,2})*', r'\1', i["compression"])
		if "e_curves" in i:
			i["e_curves"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'\1 \2', i["e_curves"])
		if "sig_alg" in i:
			i["sig_alg"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'\1 \2', i["sig_alg"])
		if "ec_point_fmt" in i:
			i["ec_point_fmt"] = re.sub(r'0x([0-9A-Fa-f]{2,2})*', r'\1', i["ec_point_fmt"])


		# Print out the rules
		print "alert tcp any any -> any any (",
		print "msg:\""+i["desc"]+"\"; ",
		# Checks for "handshake" and "record TLS Version"
		print "content: \"|16 "+i["record_tls_version"]+"|\"; offset: 0; depth: 3; rawbytes; ",
		# Checks this is a client hello packet
		print "content: \"|01|\"; distance: 1; rawbytes; ",
		# Checks TLS Version (not record, the real one)
		print "content: \"|"+i["tls_version"]+"|\"; distance: 3; rawbytes; ",
		# Depending on which output was selected use a 0 sessionid length and offset (as there is none)
		if initial:
			print "content: \"|00|\"; offset: 42; rawbytes; ",
		# Otherwise use byte_jump to jump the offset of the session_id to get to the ciphersuite section
		else:
			print "byte_jump: 1,43,align; ",
		# Lined back up now no matter which option was chosen
		print "content: \"|"+i["ciphersuite_length"]+"|\"; distance: 0; rawbytes; ",
		# CipherSuites
		print "content: \"|"+i["ciphersuite"]+"|\"; distance: 0; rawbytes; ",
		# Compression length and compression types concat'd
		print "content: \"|"+i["compression_length"]+" "+i["compression"]+"|\"; distance: 0; rawbytes; ",

		### Now we get to looping through the extensions and dealing with a few special cases where we are
		### looking at extension content, not just presence and order.

		first_ext = 0
		# This feels like a fudge, but YOLO, it's forget finesse friday \o/ XXX
		special_ext = 0
		if len(i["extensions"]) > 0:
			for x in i["extensions"].split(" "):
				# Reformat this extension to something snort-useful
				x = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'\1 \2', x)
				if first_ext == 0:
					# First extension requires a "distance: 2;" to jump it past the "extensions length" field
					print "content: \"|"+x+"|\"; rawbytes; distance: 2; ",
					first_ext += 1
				else:
					if special_ext == 0:
						print "byte_jump: 2,0,relative; ",
					else:
						special_ext = 0
					print "content: \"|"+x+"|\"; rawbytes; distance: 0; ",

				# Deal with the "special" extensions
				# XXX Should update this to include frontloading the lengths.... next
				# e_curves
				if x == "00 0A":
					special_ext = 1
					ext_len = re.sub(r'0x([0-9A-Fa-f]{1,2})', r'\1', hex((len(i["e_curves"])+1)/3))
 					ext_len = re.sub(r'^([0-9A-Fa-f])$', r'0\1 ', ext_len)
					print "content: \"|"+ext_len+i["e_curves"]+"|\"; rawbytes; distance: 0; ",
				# sig_alg
				elif x == "00 0D":
					special_ext = 1
					ext_len = re.sub(r'0x([0-9A-Fa-f]{1,2})', r'\1', hex((len(i["sig_alg"])+1)/3))
 					ext_len = re.sub(r'^([0-9A-Fa-f])$', r'0\1 ', ext_len)
					print "content: \"|"+ext_len+i["sig_alg"]+"|\"; rawbytes; distance: 0; ",
				# ec_point_fmt
				elif x == "00 0B":
					special_ext = 1
					ext_len = re.sub(r'0x([0-9A-Fa-f]{1,2})', r'\1', hex((len(i["ec_point_fmt"])+1)/3))
 					ext_len = re.sub(r'^([0-9A-Fa-f])$', r'0\1 ', ext_len)
					print "content: \"|"+ext_len+i["ec_point_fmt"]+"|\"; rawbytes; distance: 0; ",


		print "sid:"+str(sid)+"; rev:1;)"
		sid += 1
		print "\n"


def xkeyscore(filename):
	# This is my joke _joke_... ok?  JOKE!  xkeyscore (i.e. regex) exporter
	# offsets are poop in regex, don't actually use!

	# Oh python with your spaces!!!!
	jfile = read_file(filename)
	output = ''
	for i in jfile:

		# Reformat some of the values prior to printing out rules
		i["record_tls_version"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'\\x\1\\x\2', i["record_tls_version"])
		i["tls_version"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'\\x\1\\x\2', i["tls_version"])
		i["ciphersuite_length"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'\\x\1\\x\2', i["ciphersuite_length"])
		i["ciphersuite"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'\\x\1\\x\2', i["ciphersuite"])
		i["compression_length"] = re.sub(r'0x([0-9A-Fa-f]{1,2})', r'\\x\1', hex(int(i["compression_length"])))
		i["compression_length"] = re.sub(r'^([0-9A-Fa-f])$', r'\\x\1', i["compression_length"])
		i["compression"] = re.sub(r'0x([0-9A-Fa-f]{2,2})*', r'\\x\1', i["compression"])
		if "e_curves" in i:
			i["e_curves"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'\\x\1\\x\2', i["e_curves"])
		if "sig_alg" in i:
			i["sig_alg"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'\\x\1\\x\2', i["sig_alg"])
		if "ec_point_fmt" in i:
			i["ec_point_fmt"] = re.sub(r'0x([0-9A-Fa-f]{2,2})*', r'\\x\1', i["ec_point_fmt"])


		# Print out the rules
		print "# Rule for \""+i["desc"]+"\""
		output = "\"\\x16"+i["record_tls_version"]
		output = output+".*\\x01.*"+i["tls_version"]
		output = output+".*"+i["ciphersuite_length"]+i["ciphersuite"]
		output = output+".*"+i["compression"]

		### Now we get to looping through the extensions and dealing with a few special cases where we are
		### looking at extension content, not just presence and order.
		first_ext = 0
		# This feels like a fudge, but YOLO, it's forget finesse friday \o/ XXX
		special_ext = 0
		if len(i["extensions"]) > 0:
			for x in i["extensions"].split(" "):
				# Reformat this extension to something regex-useful
				x = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'\\x\1\\x\2', x)
				if first_ext == 0:
					# First extension requires a "distance: 2;" to jump it past the "extensions length" field
					output += x
					first_ext += 1
				else:
					if special_ext != 0:
						special_ext = 0
					output += x

				# Deal with the "special" extensions
				# XXX Should update this to include frontloading the lengths.... next
				# e_curves
				if x == "\\x00\\x0A":
					special_ext = 1
					ext_len = re.sub(r'0x([0-9A-Fa-f]{1,2})', r'\\x\1', hex((len(i["e_curves"])+1)/3))
 					ext_len = re.sub(r'^\\x([0-9A-Fa-f])$', r'0\1', ext_len)
					output = output+ext_len+i["e_curves"]+".*"
				# sig_alg
				elif x == "\\x00\\x0D":
					special_ext = 1
					ext_len = re.sub(r'0x([0-9A-Fa-f]{1,2})', r'\\x\1', hex((len(i["sig_alg"])+1)/3))
 					ext_len = re.sub(r'^\\x([0-9A-Fa-f])$', r'0\1', ext_len)
					output = output+ext_len+i["sig_alg"]+".*"
				# ec_point_fmt
				elif x == "\\x00\\x0B":
					special_ext = 1
					ext_len = re.sub(r'0x([0-9A-Fa-f]{1,2})', r'\\x\1', hex((len(i["ec_point_fmt"])+1)/3))
 					ext_len = re.sub(r'^\\x([0-9A-Fa-f])$', r'0\1', ext_len)
					output = output+ext_len+i["ec_point_fmt"]+".*"


		output += "\""
		output = re.sub(' ', '', output)
		print output+"\n"


def struct(filename):
	# Build struct array for use in peoples C
	# Not sorted or indexed or anything for speed, just a dump into an array... YOLO!

	# Work out longest length for string fields... awwwww yeah.. static struct joy
	desc_len = tls_version_len = ciphersuite_len = compression_len = 0
	extensions_len = e_curves_len = sig_alg_len = ec_point_fmt_len = server_name_len = 0
	record_tls_version_len = 0
	jfile = read_file(filename)
	objcount = len(jfile)

	for i in jfile:
		# This isn't very neat or nice, buuuuuuut it's not super time critical either so it stays for now.
		# Neatening this little mess up though is on the todo list
		i["ciphersuite"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'0x\1,0x\2,', i["ciphersuite"])
		i["ciphersuite"] = re.sub(r'.$', r'', i["ciphersuite"])
		i["ciphersuite"] = re.sub(r' ', r'', i["ciphersuite"])
		i["extensions"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'0x\1,0x\2,', i["extensions"])
		i["extensions"] = re.sub(r'.$', r'', i["extensions"])
		i["extensions"] = re.sub(r' ', r'', i["extensions"])
		if "compression" in i:
			i["compression"] = re.sub(r'0x([0-9A-Fa-f]{2,2})*', r'0x\1,', i["compression"])
			i["compression"] = re.sub(r'.$', r'', i["compression"])
			i["compression"] = re.sub(r' ', r'', i["compression"])
		if "e_curves" in i:
			i["e_curves"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'0x\1,0x\2,', i["e_curves"])
			i["e_curves"] = re.sub(r'.$', r'', i["e_curves"])
			i["e_curves"] = re.sub(r' ', r'', i["e_curves"])
		# XXX Need more of this checking, didn't realise how badly python would barf
		if "sig_alg" in i:
			i["sig_alg"] = re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})*', r'0x\1,0x\2,', i["sig_alg"])
			i["sig_alg"] = re.sub(r'.$', r'', i["sig_alg"])
			i["sig_alg"] = re.sub(r' ', r'', i["sig_alg"])

		if "ec_point_fmt" in i:
			i["ec_point_fmt"] = re.sub(r'0x([0-9A-Fa-f]{2,2})*', r'0x\1,', i["ec_point_fmt"])
			i["ec_point_fmt"] = re.sub(r'.$', r'', i["ec_point_fmt"])
			i["ec_point_fmt"] = re.sub(r' ', r'', i["ec_point_fmt"])


		if desc_len < len(i["desc"]):
			desc_len = len(i["desc"]) + 1
		if record_tls_version_len < len(i["record_tls_version"]):
			record_tls_version_len = len(i["record_tls_version"]) + 1
		if tls_version_len < len(i["tls_version"]):
			tls_version_len = len(i["tls_version"]) + 1
		if ciphersuite_len < ((len(i["ciphersuite"])/7) * 2):
			ciphersuite_len = ((len(i["ciphersuite"])/7) * 2)
		if compression_len < len(i["compression"]):
			compression_len = len(i["compression"]) + 1
		if extensions_len < len(i["extensions"]):
			extensions_len = len(i["extensions"]) + 1
		if "e_curves" in i:
			if e_curves_len < len(i["e_curves"]):
				e_curves_len = len(i["e_curves"]) + 1
		if "sig_alg" in i:
			if sig_alg_len < len(i["sig_alg"]):
				sig_alg_len = len(i["sig_alg"]) + 1
		if "ec_point_fmt" in i:
			if ec_point_fmt_len < len(i["ec_point_fmt"]):
				ec_point_fmt_len = len(i["ec_point_fmt"]) + 1
#		if server_name_len < len(i["server_name"]):
#			server_name_len = len(i["server_name"]) + 1

	# Print the struct layout so this can be one .c or something
	# Need to set more accurate size than "int" for the sizes
	print "struct fingerprint {"
	print "\tint id;"
	print "\tu_char desc["+str(desc_len)+"];"
	print "\tuint16_t record_tls_version;"
	print "\tuint16_t tls_version;"
	print "\tint ciphersuite_length;"
	print "\tuint8_t ciphersuite["+str(ciphersuite_len)+"];"
	print "\tint compression_length;"
	print "\tuint8_t compression["+str(compression_len)+"];"
	print "\tint extensions_length;"
	print "\tuint8_t extensions["+str(extensions_len)+"];"
	print "\tint e_curves_length;"
	print "\tuint8_t e_curves["+str(e_curves_len)+"];"
	print "\tint sig_alg_length;"
	print "\tuint8_t sig_alg["+str(sig_alg_len)+"];"
	print "\tint ec_point_fmt_length;"
	print "\tuint8_t ec_point_fmt["+str(ec_point_fmt_len)+"];"
	print "} fpdb["+str(objcount)+"] = {"

	# Pre-populate a bunch of C structs for people to use in their own Code
	# note: not ordered, indexed or in pretty trees; just at static struct array
	# enjoi the blazing performance ;)
	fp_count = 0
	for i in jfile:
		print "\t{"+str(i["id"])+", \""+i["desc"]+"\", "+i["record_tls_version"]+", "+i["tls_version"]+", ",
		print re.sub(r'0x([0-9A-Fa-f]{2,2})([0-9A-Fa-f]{2,2})$', r'0x\1\2', i["ciphersuite_length"])+", ",
		print "{"+i["ciphersuite"]+"}, "+str(i["compression_length"])+", {"+i["compression"]+"}, ",
		print str(i["extensions"].count('x'))+",",
		print "{"+i["extensions"]+"}",

		if "e_curves" in i:
			print ", "+str(i["e_curves"].count('x')),
			print ", {"+i["e_curves"]+"}",
		else:
			print ",0 , {}",
		if "sig_alg" in i:
			print ", "+str(i["sig_alg"].count('x')),
			print ", {"+i["sig_alg"]+"}",
		else:
			print ",0 , {}",
		if "ec_point_fmt" in i:
			print ", "+str(i["ec_point_fmt"].count('x')),
			print ", {"+i["ec_point_fmt"]+"}",
		else:
			print ",0 , {}",

		fp_count += 1

		if fp_count < objcount:
			print "},"
		else:
			print "}"


	print "\t};"

def binary(filename):

	# XXX accounted for 0x00 where 0x0000 is needed, have not looked at 0x0 yet... check this!!

	# XXX Check the mutt signature with the oddly formed compression len to compression thing

	# Build a binary "database", which is actually a pre-compiled'ish struct linked list for use in peoples code
	# Much like the "struct" option but allows more room for indexing/searching and growing as there is no need
	# to parse strings from some flatfile which C is soooooo good at.  Yes yes, this is still file parsing....
	# but (from a C perspective) it's easier file parsing, and this isn't so hard in python to output either.

	# Documenting the file format here, in lieu of proper documentation

	# Byte 0			: binary format version
	# Per fingerprint.....
	# uint16_t			: Fingerprint ID
	# uint16_t		 	: Desc Length
	# Bytes <above>		: Desc
	# uint16_t <next>	: record_tls_version;
	# uint16_t <next>	: tls_version;
	# etc etc etc
	# uint16_t ciphersuite_length
	# uint8_t ciphersuite....
	# uint8_t compression_length
	# uint8_t compression....
	# uint16_t extensions_length
	# uint8_t extensions....
	# uint16_t e_curves_length
	# uint8_t e_curves.....
	# uint16_t sig_alg_length
	# uint8_t sig_alg.....
	# uint16_t ec_point_fmt_length
	# uint8_t ec_point_fmt....


	# Write the version before we itterate through the fingerprints
	outfile = open("tlsfp.db","w+")
	outfile.write(byte_to_bin("0x00"))

	# Open the JSON file and process each entry (line)
	jfile = read_file(filename)
	objcount = len(jfile)

	for i in jfile:
		# Need to add the ID once this is working XXX
		print "Processing: "+i["desc"]
		# Initialise all the lengths to stop things complaining later.  Oh and other random
		# weirdness.
		desc_len = tls_version_len = ciphersuite_len = compression_len = 0
		extensions_len = e_curves_len = sig_alg_len = ec_point_fmt_len = server_name_len = 0
		record_tls_version_len = 0

		# Start correctly encoding things and writing them to outfile
		temp_data = format(i["id"], '#06x')
		outfile.write(byte_to_bin(temp_data))

		temp_data = len(i["desc"])
		temp_data = format(temp_data, '#06x')
		outfile.write(byte_to_bin(temp_data))

		outfile.write(i["desc"])
		outfile.write(byte_to_bin(i["record_tls_version"]))
		outfile.write(byte_to_bin(i["tls_version"]))
		outfile.write(byte_to_bin(i["ciphersuite_length"]))
		outfile.write(byte_to_bin(i["ciphersuite"]))

		# Compression Length is stored as decimal for some reason (go team)
		# But it's only a one byte value... ccccoooonnnnvvveeeerrrrttttt
		temp_data = len(byte_to_bin(i["compression"].zfill(2)))
		temp_data = format(temp_data, '#04x')
		outfile.write(byte_to_bin(temp_data))

		# OK, carry on as we were...
		outfile.write(byte_to_bin(i["compression"]))

		# We need to calculate extensions_length, because it's not in the JSON file
		# so switcharoo, encode extensions first, then length it, then write... *BOOM*
		temp_data = len(byte_to_bin(i["extensions"]))
		temp_data = format(temp_data, '#06x')
		outfile.write(byte_to_bin(temp_data))
		outfile.write(byte_to_bin(i["extensions"]))

		# And again for the optionals
		if "e_curves" in i:
			temp_data = len(byte_to_bin(i["e_curves"]))
			temp_data = format(temp_data, '#06x')
			outfile.write(byte_to_bin(temp_data))
			outfile.write(byte_to_bin(i["e_curves"]))
		else:
			# Still need to set zero length
			outfile.write(byte_to_bin("0x0000"))

		if "sig_alg" in i:
			temp_data = len(byte_to_bin(i["sig_alg"]))
			temp_data = format(temp_data, '#06x')
			outfile.write(byte_to_bin(temp_data))
			outfile.write(byte_to_bin(i["sig_alg"]))
		else:
			# Still need to set zero length
			outfile.write(byte_to_bin("0x0000"))

		if "ec_point_fmt" in i:
			temp_data = len(byte_to_bin(i["ec_point_fmt"]))
			temp_data = format(temp_data, '#06x')
			outfile.write(byte_to_bin(temp_data))
			outfile.write(byte_to_bin(i["ec_point_fmt"]))
		else:
			# Still need to set zero length
			outfile.write(byte_to_bin("0x0000"))

	# Close the file before the script terminates
	outfile.close()


if __name__ == '__main__':
	parser = argparse.ArgumentParser()

	action_group = parser.add_mutually_exclusive_group(required=True)
	action_group.add_argument("-c", "--cleanse", action="store_true",
							  help="Re-output as JSON with some format un-breaking (beta)")
	action_group.add_argument("-s", "--struct", action="store_true",
							  help="Output C Structure")
	action_group.add_argument("-b", "--binary", action="store_true",
							  help="Output binary fingerprint DB")
	action_group.add_argument("-i", "--ids", action="store_true",
							  help="Output Suricata/Snort Signatures")
	action_group.add_argument("-I", "--idsinit", action="store_true",
							  help="Output Suricata/Snort Signatures matching only initial handshake (sessionid 0)")
	action_group.add_argument("-x", "--xkeyscore", action="store_true",
							  help="OK, it's regex, and not that great, probably best not to use this!")

	parser.add_argument('filename', nargs='?', help="Specify the fingerprint file to use")
	parser.add_argument('outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout,
						help="You may optionally supply an output file, otherwise output to stdout")

	args = parser.parse_args()

	sys.stdout = args.outfile

	if args.cleanse:
		cleanse(args.filename)
	elif args.struct:
		struct(args.filename)
	elif args.binary:
		binary(args.filename)
	elif args.ids:
		ids(args.filename)
	elif args.idsinit:
		ids(args.filename, initial=True)
	elif args.xkeyscore:
		xkeyscore(args.filename)
	else:
		parser.print_usage()
