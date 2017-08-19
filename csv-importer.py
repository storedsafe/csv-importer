#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
csv-importer.py: Assist in parsing CSV files and output either a properly formatted JSON file suitable
  for import into StoredSafe or utilize the REST API to do a direct import to StoredSafe.
"""

from __future__ import print_function
import sys
import ssl
import OpenSSL
import csv
import json
import getopt
import getpass
import os.path
import re
import pprint
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
 
__author__     = "Fredrik Soderblom"
__copyright__  = "Copyright 2017, AB StoredSafe"
__license__    = "GPL"
__version__    = "1.0.1"
__maintainer__ = "Fredrik Soderblom"
__email__      = "fredrik@storedsafe.com"
__status__     = "Production"

# Globals

url              = False
token            = False
verbose          = False
debug            = False
create_vault     = False
allow_duplicates = False
no_rest          = False
skip_first       = False
delete_extra     = False
munch_stdin      = False
objectname       = 'host'

def main():
  global token, url, verbose, debug, create_vault, allow_duplicates, no_rest, skip_first, delete_extra, munch_stdin, objectname

  # Some default values
  templateid = '1'
  template = 'Server'
  fieldnames = [ 'host', 'username', 'password', 'info', 'cryptedinfo' ]
  separator = ','
  list_templates = list_fieldnames = list_vaults = False
  user = apikey = supplied_token = storedsafe = rc_file = vaultid = vaultname = outfile = infile = ''

  try:
   opts, args = getopt.getopt(sys.argv[1:], "s:u:a:v:t:?",\
    [ "verbose", "debug", "storedsafe=", "token=", "user=", "apikey=", "vault=", "vaultid=",\
     "template=", "templateid=", "rc=", "csv=", "json=", "create-vault", "allow-duplicates",\
     "no-rest", "fieldnames=", "separator=", "objectname=", "skip-first-line", "remove-extra-columns",\
     "list-templates", "list-fieldnames", "list-vaults", "help" ])
  except getopt.GetoptError as err:
    print("%s" % str(err))
    usage()
    sys.exit()

  if opts:
    pass
  else:
    usage()
    sys.exit()

  for opt, arg in opts:
    if opt in ("--verbose"):
      verbose = True
    elif opt in ("--debug"):
      debug = True
      verbose = True
    elif opt in ("-s", "--storedsafe"):
      storedsafe = arg
    elif opt in ("-u", "--user"):
      user = arg
    elif opt in ("-a", "--apikey"):
      if len(str(arg)) == 10:
        apikey = arg
      else:
        print("Invalid API key.")
        sys.exit()
    elif opt in ("-t", "--token"):
      if len(str(arg)) == 42:
        supplied_token = arg
      else:
        print("Invalid token.")
        sys.exit()
    elif opt in ("--rc"):
      rc_file = arg
    elif opt in ("-v", "--vault"):
      vaultname = arg
    elif opt in ("--vaultid"):
      vaultid = arg
    elif opt in ("--template"):
      template = arg
    elif opt in ("--templateid"):
      templateid = arg
    elif opt in ("--csv"):
      infile = arg
    elif opt in ("--separator"):
      separator = arg
    elif opt in ("--json"):
      outfile = arg
    elif opt in ("--fieldnames"):
      fieldnames = arg.split(',')
    elif opt in ("--create-vault"):
      create_vault = True
    elif opt in ("--objectname"):
      objectname = arg
    elif opt in ("--allow-duplicates"):
      allow_duplicates = True
    elif opt in ("--no-rest"):
      no_rest = True
    elif opt in ("--skip-first-line", "--skip"):
      skip_first = True
    elif opt in ("--remove-extra-columns", "--remove"):
      delete_extra = True
    elif opt in ("--list-vaults", "--vaults"):
      list_vaults = True
    elif opt in ("--list-templates", "--templates"):
      list_templates = True
    elif opt in ("--list-fieldnames", "--fieldnames"):
      list_fieldnames = True
    elif opt in ("-?", "--help"):
      usage()
      sys.exit()
    else:
      assert False, "Unrecognized option"

  # No input file, read from stdin
  if not infile:
    munch_stdin = True

  #
  # No connection to server required/available, just format and dump to screen or file
  #

  if no_rest:
    lines = CSVRead(infile, template, fieldnames, separator)
    data = {}
    data[template] = lines

    if outfile:
      output = open(outfile, 'w')
      output.write(json.dumps(data, indent=4, ensure_ascii=False, encoding="utf-8"))
      output.close()
    else:
      print(json.dumps(data, indent=4, ensure_ascii=False, encoding="utf-8"))

    sys.exit(0)

  #
  # REST mode, on-line importing
  #

  if supplied_token:
    token = supplied_token
  if rc_file:
    (storedsafe, token) = readrc(rc_file)
  
  url = "https://" + storedsafe + "/api/1.0"

  if not token:
    if user and apikey:
      pp = passphrase(user)
      otp = OTP(user)
      token = login(user, pp + apikey + otp)
    else:
      print("INFO: You need to either specify operation without REST connectivity (--no-rest) or supply valid credentials. (--user, --apikey, --token or --rc).")
      sys.exit()

  if not authCheck():
    sys.exit()

  # Just list vaults available to the current logged in user
  if list_vaults:
    listVaults()
    sys.exit()

  # List all available templates on the server
  if list_templates:
    listTemplates()
    sys.exit()

  # Check if Template-ID exists, return Template name
  if templateid:
    template = findTemplateName(templateid)

  # Check if Template exists, return Template-ID
  if template:
    templateid = findTemplateID(template)

  # List the fields in a given Template-ID
  if list_fieldnames:
    print(','.join(getFieldNames(templateid)))
    sys.exit()

  # Extract field names, unless given on command line
  if not fieldnames:
    fieldnames = getFieldNames(templateid)

  # Check if Vaultname exists, returns Vault-ID
  if vaultname:
    vaultid = findVaultID(vaultname)

  # Check if Vault-ID exists, returns Vault name
  if vaultid:
    vaultname = findVaultName(vaultid)
  else:
    if not create_vault:
      print("ERROR: One of \"--vault\", \"--vaultid\" or \"--create-vault\" is mandatory.")
      sys.exit()

  # Read input and import via REST
  data = CSVRead(infile, template, fieldnames, separator)
  (imported, duplicates) = insertObjects(data, templateid, fieldnames, vaultid)

  if imported:
    if verbose: print("INFO: Imported %d object/s" % imported)
  if duplicates:
    if verbose or not imported: 
      print("WARNING: Skipped %d duplicate object/s." % duplicates)
    sys.exit(1)

  sys.exit(0)

def usage():
  print("Usage: %s [-vdsuat]" % sys.argv[0])
  print(" --verbose (or -v)              (Boolean) Enable verbose output.")
  print(" --debug (or -d)                (Boolean) Enable debug output.")
  print(" --rc <rc file>                 Use this file to obtain a valid token and a server address.")
  print(" --storedsafe (or -s) <Server>  Use this StoredSafe server.")
  print(" --user (or -u) <user>          Authenticate as this user to the StoredSafe server.")
  print(" --apikey (or -a) <API Key>     Use this unique API key when communicating with the StoredSafe server.")
  print(" --token (or -t) <Auth Token>   Use pre-authenticated token instead of --user and --apikey.")
  print(" --csv <file>                   File in CSV format to import.")
  print(" --separator <char>             Use this character as CSV delimiter. (defaults to ,)")
  print(" --json <file>                  Store output (JSON) in this file.")
  print(" --fieldnames <fields>          Specify the mapping between columns and field names. Has to match exactly. Defaults to the Server template.")
  print(" --template <template>          Use this template name for import. Name has to match exactly. Defaults to the Server template.")
  print(" --templateid <template-ID>     Use this template-ID when importing.")
  print(" --vault <Vaultname>            Store imported objects in this vault. Name has to match exactly.")
  print(" --vaultid <Vault-ID>           Store imported objects in this Vault-ID.")
  print(" --objectname <field>           Use this field as objectname when storing objects. (Defaults to the host field from the Server template)")
# print(" --create-vault                 (Boolean) Create missing vaults.") # NOTIMPL
  print(" --allow-duplicates             (Boolean) Allow duplicates when importing.")
  print(" --no-rest                      Operate in off-line mode, do not attempt to use the REST API.")
  print(" --skip-first-line              Skip first line of input. A CSV file usually has headers, use this to skip them.")
  print(" --remove-extra-columns         Remove any extra columns the if CSV file has more columns than the template.")
# print(" --stuff-extra-in <field>       Add data from extranous columns to this field.") # NOTIMPL
  print(" --list-vaults                  List all vaults accessible to the authenticated user.")
  print(" --list-templates               List all available templates.")
  print(" --list-fieldnames              List all fieldnames in the specified template. (--template or --templateid)")
  print("\nUsing REST API and interactive login:")
  print("$ %s --storedsafe safe.domain.cc --user bob --apikey myapikey --csv file.csv --vault \"Public Web Servers\" --verbose" % sys.argv[0])
  print("\nUsing REST API and pre-authenticated login:")
  print("$ %s --rc ~/.storedsafe-client.rc --vault \"Public Web Servers\" --csv file.csv" % sys.argv[0])
  print("\nOff-line mode:")
  print("$ %s --no-rest --csv file.csv --json file.json --template Login --fieldnames host,username,password" % sys.argv[0])

def readrc(rc_file):
  if os.path.isfile(rc_file):
    f = open(rc_file, 'rU')
    for line in f:
      if "token" in line:
        token = re.sub('token:([a-zA-Z0-9]+)\n$', r'\1', line)
        if token == 'none':
          print("ERROR: No valid token found in \"%s\". Have you logged in?" % rc_file)
          sys.exit()
      if "mysite" in line:
        server = re.sub('mysite:([a-zA-Z0-9.]+)\n$', r'\1', line)
        if server == 'none':
          print("ERROR: No valid server specified in \"%s\". Have you logged in?" % rc_file)
          sys.exit()
    f.close()
    if not token:
      print("ERROR: Could not find a valid token in \"%s\"" % rc_file)
      sys.exit()
    if not server:
      print("ERROR: Could not find a valid server in \"%s\"" % rc_file)
      sys.exit()
    return (server, token)
  else:
    print("ERROR: Can not open \"%s\"." % rc_file)

def passphrase(user):
  p = getpass.getpass('Enter ' + user + '\'s passphrase: ')
  return(p)

def OTP(user):
  otp = getpass.getpass('Press ' + user + '\'s Yubikey: ')
  return(otp)

def login(user, key):
  global url

  payload = { 'username': user, 'keys': key }
  try:
    r = requests.post(url + '/auth', data=json.dumps(payload))
  except:
    print("ERROR: No connection to \"%s\"" % url)
    sys.exit()
  data = json.loads(r.content)
  if r.ok:
    return data["CALLINFO"]["token"]
  else:
    print("ERROR: %s" % data["ERRORS"][0])
    sys.exit()

def authCheck():
  global token, url, verbose, debug

  payload = { 'token': token }
  try:
    r = requests.post(url + '/auth/check', data=json.dumps(payload))
  except:
    print("ERROR: Can not reach \"%s\"" % url)
    sys.exit()

  data = json.loads(r.content)
  if not r.ok:
    print("Not logged in.")
    sys.exit()

  if data["CALLINFO"]["status"] == 'SUCCESS':
    if debug: print("DEBUG: Authenticated using token \"%s\"." % token)
  else:
    print("ERROR: Session not authenticated with server. Token invalid?")
    return(False)

  return(True)

def findVaultID(vaultname):
  global token, url, verbose, debug

  vaultid = False

  payload = { 'token': token }
  try:
    r = requests.get(url + '/vault', params=payload)
  except:
    print("ERROR: No connection to \"%s\"" % url)
    sys.exit()
  data = json.loads(r.content)
  if not r.ok:
    print("ERROR: Can not find any vaults.")
    sys.exit()

  for v in data["GROUP"].iteritems():
    if vaultname == data["GROUP"][v[0]]["groupname"]:
      vaultid = v[0]
      if debug: print("DEBUG: Found Vault \"%s\" via Vaultname as Vault-ID \"%s\"" % (vaultname, vaultid))

  if not vaultid:
    if create_vault:
      print("ERROR: Can not find Vaultname \"%s\", will try to create a new vault." % vaultname)
      vaultid = False
    else:
      print("ERROR: Can not find Vaultname \"%s\" and \"--create-vault\" not specified." % vaultname)   
      sys.exit()

  return(vaultid)

def findVaultName(vaultid):
  global token, url, create_vault, verbose, debug

  payload = { 'token': token }
  try:
    r = requests.get(url + '/vault/' + vaultid, params=payload)
  except:
    print("ERROR: No connection to \"%s\"" % url)
    sys.exit()
  data = json.loads(r.content)
  if not r.ok:
    if create_vault:
      print("WARNING: Can not find Vault-ID \"%s\", will try to create a new vault." % vaultid)
      vaultname = False
    else:
      print("ERROR: Can not find Vault-ID \"%s\" and \"--create-vault\" not specified." % vaultid)
      sys.exit()

  if data["CALLINFO"]["status"] == "SUCCESS":
    vaultname = data["GROUP"][vaultid]["groupname"]
    if debug: print("DEBUG: Found Vault \"%s\" via Vault-ID \"%s\"" % (vaultname, vaultid))
  else:
    print("ERROR: Can not retreive Vaultname for Vault-ID %s." % vaultid)
    sys.exit()

  return(vaultname)

def getFieldNames(templateid):
  global token, url, verbose, debug

  payload = { 'token': token }
  try:
    r = requests.get(url + '/template/' + templateid, params=payload)
  except:
    print("ERROR: No connection to \"%s\"" % url)
    sys.exit()
  if not r.ok:
    print("ERROR: Can not find Template-ID \"%s\"." % templateid)
    sys.exit()

  data = json.loads(r.content)
  if data["CALLINFO"]["status"] == "SUCCESS":
    template = data["TEMPLATE"][templateid]["INFO"]["name"]
    if debug: print("DEBUG: Found Template \"%s\" via Template-ID \"%s\"" % (template, templateid))
  else:
    print("ERROR: Can not retreive Template for Template-ID %s." % templateid)
    sys.exit()

  fieldnames = []
  for v in data["TEMPLATE"][templateid]['STRUCTURE']:
    fieldnames.append(v)

  return fieldnames

def listTemplates():
  global token, url, verbose, debug

  template = False
  templateid = False

  payload = { 'token': token }
  try:
    r = requests.get(url + '/template', params=payload)
  except:
    print("ERROR: No connection to \"%s\"" % url)
    sys.exit()
  data = json.loads(r.content)
  if not r.ok:
    print("ERROR: Can not find any templates.")
    sys.exit()

  for v in data["TEMPLATE"].iteritems():
    template = data["TEMPLATE"][v[0]]["INFO"]["name"]
    templateid = v[0]
    print("Found Template \"%s\" as Template-ID \"%s\"" % (template, templateid))

  return

def listVaults():
  global token, url, verbose, debug

  vaultname = False
  vaultid = False

  payload = { 'token': token }
  try:
    r = requests.get(url + '/vault', params=payload)
  except:
    print("ERROR: No connection to \"%s\"" % url)
    sys.exit()
  data = json.loads(r.content)
  if not r.ok:
    print("ERROR: Can not find any vaults.")
    sys.exit()

  for v in data["GROUP"].iteritems():
    vaultname = data["GROUP"][v[0]]["groupname"]
    vaultid = v[0]
    print("Vault \"%s\" (Vault-ID \"%s\")" % (vaultname, vaultid))

  return

def findTemplateID(template):
  global token, url, verbose, debug

  templateid = False

  payload = { 'token': token }
  try:
    r = requests.get(url + '/template', params=payload)
  except:
    print("ERROR: No connection to \"%s\"" % url)
    sys.exit()
  data = json.loads(r.content)
  if not r.ok:
    print("ERROR: Can not find any templates.")
    sys.exit()

  for v in data["TEMPLATE"].iteritems():
    if template == data["TEMPLATE"][v[0]]["INFO"]["name"]:
      templateid = v[0]
      if debug: print("DEBUG: Found Template \"%s\" as Template-ID \"%s\"" % (template, templateid))

  if not templateid:
    print("ERROR: Can not find Template \"%s\"." % template)   
    sys.exit()

  return(templateid)

def findTemplateName(templateid):
  global token, url, verbose, debug

  payload = { 'token': token }
  try:
    r = requests.get(url + '/template/' + templateid, params=payload)
  except:
    print("ERROR: No connection to \"%s\" (1)" % url)
    sys.exit()
  data = json.loads(r.content)
  if not r.ok:
    print("ERROR: Can not find Template-ID \"%s\"." % templateid)
    sys.exit()

  if data["CALLINFO"]["status"] == "SUCCESS":
    template = data["TEMPLATE"][templateid]["INFO"]["name"]
    if debug: print("DEBUG: Found Template \"%s\" via Template-ID \"%s\"" % (template, templateid))
  else:
    print("ERROR: Can not retreive Template for Template-ID %s." % templateid)
    sys.exit()

  return(template)

def CSVRead(infile, template, fieldnames, separator):
  global skip_first, delete_extra, munch_stdin

  if munch_stdin:
    file = sys.stdin
  else:
    try:
      file = open(infile, 'rb')
    except:
      print("ERROR: Could not open \"%s\"" % infile)
      sys.exit()

  reader = csv.DictReader(file, delimiter=separator, fieldnames=fieldnames, restkey="unspecified-columns")

  if skip_first:
    reader.next()

  lines = []
  for line in reader:
    if delete_extra:
    	if 'unspecified-columns' in line:
    		del line['unspecified-columns']
    lines.append(line)

  return lines

def getObjects(vaultid):
  global token, url, verbose, debug

  payload = { 'token': token }
  try:
    r = requests.get(url + '/vault/' + vaultid, params=payload)
  except:
    print("ERROR: No connection to \"%s\"" % url)
    sys.exit()
  data = json.loads(r.content)
  if not r.ok:
    print("ERROR: Can not find any vaults.")
    sys.exit()

  if debug: print("DEBUG: Getting objects in Vault \"%s\" (Vault-ID %s)" % (data['GROUP'][vaultid]['groupname'], vaultid))

  objects = {}

  if (len(data['OBJECT'])):
    for v in data['OBJECT'].iteritems():
      objects[v[0]] = v[1]

  return objects

def find_duplicates(line, templateid, vaultid):
  global objectname

  candidate = match = 0
  duplicate = False

  vaultname = findVaultName(vaultid)
  fieldnames = getFieldNames(templateid)
  objects = getObjects(vaultid)

  if verbose: print("INFO: Searching thru Vault \"%s\" (Vault-ID %s) for duplicates of \"%s\"." % (vaultname, vaultid, line['objectname']))
  for key in objects.keys():

    if objects[key]['templateid'] == templateid:

      if debug: print(" DEBUG: Examining object \"%s\" (Object-ID %s)" % (objects[key]['objectname'], key))

      if 'objectname' in objects[key]:
        if objects[key]['objectname'] == line['objectname']:
          candidate += 1
          if debug: print("   DEBUG: Field matched. (%d total matche/s)" % (candidate))

      for fieldname in fieldnames:
        if fieldname in objects[key]['public']:
          if debug: print("  DEBUG: Examine \"%s\": found \"%s\" (compare with \"%s\")" % (fieldname, objects[key]['public'][fieldname], line[fieldname]))
          if objects[key]['public'][fieldname] == line[fieldname]:
            candidate += 1
            if debug: print("   DEBUG: Field matched. (%d total matche/s)" % (candidate))

      if (candidate >= 3):
        match += 1
        if verbose: print(" INFO: Object \"%s\" (Object-ID %s) (%d field/s matched) - Duplicate." % (objects[key]['objectname'], key, candidate))
      else:
        if debug: print(" DEBUG: Object \"%s\" (Object-ID %s) (%d field/s matched)" % (objects[key]['objectname'], key, candidate))

      candidate = 0

    else:
      if debug: print("DEBUG: Wrong template (#%s), skipping." % (objects[key]['templateid']))

  if (match >= 1):
    duplicate = True
    if verbose: print("INFO: When importing \"%s\" to Vault \"%s\", %s object/s appeared identical, marking as a duplicate and skipping. (Use \"--allow-duplicates\" to force import)" % (line['objectname'], vaultname, match))
  else:
    if verbose: print("INFO: \"%s\" has no duplicates in Vault \"%s\"." % (line['objectname'], vaultname))

  return(duplicate)

def insertObjects(lines, templateid, fieldnames, vaultid):
  global token, url, verbose, create_vault, allow_duplicates, objectname

  exists = False
  imported = duplicates = 0

  for line in lines:
    line['objectname'] = line[objectname]

    if not allow_duplicates:
      exists = find_duplicates(line, templateid, vaultid)

    if not exists:
      line['token'] = token
      line['templateid'] = templateid
      line['groupid'] = vaultid
      line['parentid'] = "0"
      r = requests.post(url + '/object', json=line)
      if not r.ok:
        print("ERROR: Could not save object \"%s\"" % line['objectname'])
        sys.exit()
      imported += 1
    else:
      duplicates += 1

  return(imported, duplicates)

if __name__ == '__main__':
  main()