# -*- coding: utf-8 -*-
"""
Created on Tue Jun 16 10:41:31 2015

@author: r4
"""
__author__ = 'r4'

##

import json
import http.client as httplib
import mimetypes
import urllib.parse as urlparse
import csv
import time
import os
import glob
import socket
import requests

# Hack to to deal with ethernet vs wlan
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager

class SourceAddressAdapter(HTTPAdapter):
    def __init__(self, source_address, **kwargs):
        self.source_address = source_address

        super(SourceAddressAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       source_address=self.source_address)

#Get wireless IP (un-firewalled)
IP = socket.gethostbyname_ex(socket.gethostname())[2]
for add in IP:
    if add.startswith('192'):
        IP = add
        break
# Create a single session (instance) with bound IP. Tuple is (IP,Port) with port 0 denoting random and high.
session = requests.Session()
session.mount('http://', SourceAddressAdapter((IP,0)))
session.mount('https://', SourceAddressAdapter((IP,0)))




def authenticate(hostname, client_id, client_secret, username, password):
    """ Authenticate via username/password. Returns json token object.

    Args:
    string hostname - hostname like "myaccount.sharefile.com"
    string client_id - OAuth2 client_id key
    string client_secret - OAuth2 client_secret key
    string username - my@user.name
    string password - my password """

    uri_path = '/oauth/token'

    headers = {'Content-Type':'application/x-www-form-urlencoded'}
    params = {'grant_type':'password', 'client_id':client_id, 'client_secret':client_secret,
              'username':username, 'password':password}

    url="https://"+hostname+uri_path
    response = requests.post(url,params)

    print(response.status_code, response.reason)
    token = None
    if response.status_code == 200:
        token = response.json()
        print('Received token info', token)

    return token

def get_authorization_header(token):
    return {'Authorization':'Bearer %s'%(token['access_token'])}

def get_hostname(token):
    return '%s.sf-api.com'%(token['subdomain'])

def get_root(token, get_children=False):
    """ Get the root level Item for the provided user. To retrieve Children the $expand=Children
    parameter can be added.

    Args:
    dict json token acquired from authenticate function
    boolean get_children - retrieve Children Items if True, default is False"""

    uri_path = '/sf/v3/Items(allshared)'
    if get_children:
        uri_path+='?$expand=Children'
    #print('GET %s%s'%(get_hostname(token), uri_path))
    url= "https://"+get_hostname(token)+uri_path

    # httplib.HTTPConnection.debuglevel = 1
    # logging.basicConfig()
    # logging.getLogger().setLevel(logging.DEBUG)
    # requests_log = logging.getLogger("requests.packages.urllib3")
    # requests_log.setLevel(logging.DEBUG)
    # requests_log.propagate = True

    header=get_authorization_header(token)
    response=session.get(url,headers=header,verify=True)
    print(response.status_code, response.reason)
    items = response.json()
    print(items['Id'], items['CreationDate'], items['Name'])
    if 'Children' in items:
        children = items['Children']
        for child in children:
           print(child['Id'], items['CreationDate'], child['Name'])

def get_item_by_path(token,file_path):
    uri_path = '/sf/v3/Items/ByPath?path='+file_path
    url = 'https://'+get_hostname(token)+uri_path
    print('GET ' +'https://'+ get_hostname(token) + uri_path)

    response = session.get(url,headers=get_authorization_header(token))
    out=response.json()

    print(response.status_code, response.reason)
    return out['Id']

def get_item_by_id(token, item_id):
    """ Get a single Item by Id.

    Args:
    dict json token acquired from authenticate function
    string item_id - an item id """

    uri_path = '/sf/v3/Items(%s)'%(item_id)
    print('GET %s%s'%(get_hostname(token), uri_path))
    http = httplib.HTTPSConnection(get_hostname(token))
    http.request('GET', uri_path, headers=get_authorization_header(token))
    response = http.getresponse()

    print(response.status, response.reason)
    items = json.loads(response.read().decode('utf-8'))
    print(items['Id'], items['CreationDate'], items['Name'])

def get_folder_with_query_parameters(token, item_id):
    """ Get a folder using some of the common query parameters that are available. This will
    add the expand, select parameters. The following are used:

    expand=Children to get any Children of the folder
    select=Id,Name,Children/Id,Children/Name,Children/CreationDate to get the Id, Name of the folder
    and the Id, Name, CreationDate of any Children

    Args:
    dict json token acquired from authenticate function
    string item_id - a folder id """

    uri_path = '/sf/v3/Items(%s)?$expand=Children&$select=Id,Name,Children/Id,Children/Name,Children/CreationDate'%(item_id)
    url= "https://"+get_hostname(token)+uri_path
    response = session.get(url,headers=get_authorization_header(token))
    print(response.status_code, response.reason)
    items = response.json()
    #print(items['Name'], items['Id']) #Print parent/root node (direct call).
    if 'Children' in items:
        children = items['Children']
        for child in children:
           print(child['Name'], child['Id'])

    return children

def create_folder(token, parent_id, name, description):
    """ Create a new folder in the given parent folder.

    Args:
    dict json token acquired from authenticate function
    string parent_id - the parent folder in which to create the new folder
    string name - the folder name
    string description - the folder description """

    uri_path = '/sf/v3/Items(%s)/Folder'%(parent_id)
    print('POST %s%s'%(get_hostname(token), uri_path))
    folder = {'Name':name, 'Description':description}
    headers = get_authorization_header(token)
    headers['Content-Type'] = 'application/json'
    http = httplib.HTTPSConnection(get_hostname(token))
    http.request('POST', uri_path, json.dumps(folder), headers=headers)
    response = http.getresponse()

    print(response.status, response.reason)
    new_folder = json.loads(response.read().decode('utf-8'))
    print('Created Folder %s'%(new_folder['Id']))

    http.close()

def update_item(token, item_id, name, description):
    """ Update the name and description of an Item.

    Args:
    dict json token acquired from authenticate function
    string item_id - the id of the item to update
    string name - the item name
    string description - the item description """


    uri_path = '/sf/v3/Items(%s)'%(item_id)
    print('PATCH %s%s'%(get_hostname(token), uri_path))
    folder = {'Name':name, 'Description':description}
    headers = get_authorization_header(token)
    headers['Content-type'] = 'application/json'
    http = httplib.HTTPSConnection(get_hostname(token))
    http.request('PATCH', uri_path, json.dumps(folder), headers=headers)
    response = http.getresponse()

    print(response.status, response.reason)
    http.close()

def delete_item(token, item_id):
    """ Delete an Item by Id.

    Args:
    dict json token acquired from authenticate function
    string item_id - the id of the item to delete """

    uri_path = '/sf/v3/Items(%s)'%(item_id)
    print('DELETE %s%s'%(get_hostname(token), uri_path))
    http = httplib.HTTPSConnection(get_hostname(token))
    http.request('DELETE', uri_path, headers=get_authorization_header(token))
    response = http.getresponse()

    print(response.status, response.reason)
    http.close()

def download_item(token, item_id, local_path):
    """ Downloads a single Item. If downloading a folder the local_path name should end in .zip.

    Args:
    dict json token acquired from authenticate function
    string item_id - the id of the item to download
    string local_path - where to download the item to, like "c:\path\to\the.file" """

    uri_path = '/sf/v3/Items(%s)/Download'%(item_id)
    print('GET %s%s'%(get_hostname(token), uri_path))
    http = httplib.HTTPSConnection(get_hostname(token))
    http.request('GET', uri_path, headers=get_authorization_header(token))
    response = http.getresponse()
    location = response.getheader('location')
    redirect = None
    if location:
        redirect_uri = urlparse.urlparse(location)
        redirect = httplib.HTTPSConnection(redirect_uri.netloc)
        redirect.request('GET', '%s?%s'%(redirect_uri.path, redirect_uri.query))
        response = redirect.getresponse()

    with open(local_path, 'wb') as target:
        b = response.read(1024*8)
        while b:
            target.write(b)
            b = response.read(1024*8)

    print(response.status, response.reason)
    http.close()
    if redirect:
        redirect.close()

def upload_file(token, folder_id, local_path):
    """ Uploads a File using the Standard upload method with a multipart/form mime encoded POST.

    Args:
    dict json token acquired from authenticate function
    string folder_id - where to upload the file
    string local_path - the full path of the file to upload, like "c:\path\to\file.name" """

    uri_path = '/sf/v3/Items(%s)/Upload'%(folder_id)
    print('GET %s%s'%(get_hostname(token), uri_path))
    http = httplib.HTTPSConnection(get_hostname(token))
    http.request('GET', uri_path, headers=get_authorization_header(token))

    response = http.getresponse()
    upload_config = json.loads(response.read().decode('utf-8'))
    if 'ChunkUri' in upload_config:
        upload_response = multipart_form_post_upload(upload_config['ChunkUri'], local_path)
        print(upload_response.status, upload_response.reason)
        if upload_response.status!=200:
            print("ERROR ERROR ERROR "+local_path+"failed to upload!")
            raise ValueError('Recieved Response Status: '+upload_response.status+ ' ' + upload_response.reason+
                             '. \r\n Expected 200 OK!')
    else:
       print('No Upload URL received')

def multipart_form_post_upload(url, filepath):
    """ Does a multipart form post upload of a file to a url.

    Args:
    string url - the url to upload file to
    string filepath - the complete file path of the file to upload like, "c:\path\to\the.file

    Returns:
    the http response """

    newline = b'\r\n'
    filename = os.path.basename(filepath)
    data = []
    headers = {}
    boundary = '----------%d' % int(time.time())
    headers['content-type'] = 'multipart/form-data; boundary=%s' % boundary
    data.append(('--%s' % boundary).encode('utf-8'))
    data.append(('Content-Disposition: form-data; name="%s"; filename="%s"' % ('File1', filename)).encode('utf-8'))
    data.append(('Content-Type: %s' % get_content_type(filename)).encode('utf-8'))
    data.append(('').encode('utf-8'))
    data.append(open(filepath, 'rb').read())
    data.append(('--%s--' % boundary).encode('utf-8'))
    data.append(('').encode('utf-8'))
    print(data)
    data_str = newline.join(data)
    headers['content-length'] = len(data_str)

    uri = urlparse.urlparse(url)
    http = httplib.HTTPSConnection(uri.netloc)
    http.putrequest('POST', '%s?%s'%(uri.path, uri.query))
    for hdr_name, hdr_value in headers.items():
        http.putheader(hdr_name, hdr_value)
    http.endheaders()
    http.send(data_str)
    return http.getresponse()

def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

def get_clients(token):
    """ Get the Client users in the Account.

    Args:
    dict json token acquired from authenticate function """

    uri_path = '/sf/v3/Accounts/GetClients'
    print('GET %s%s'%(get_hostname(token), uri_path))
    http = httplib.HTTPSConnection(get_hostname(token))
    http.request('GET', uri_path, headers=get_authorization_header(token))
    response = http.getresponse()

    print(response.status, response.reason)
    feed = json.loads(response.read().decode('utf-8'))
    if 'value' in feed:
        for client in feed['value']:
           print(client['Id'], client['Email'])

def create_client(token, email, firstname, lastname, company,
                  clientpassword, canresetpassword, canviewmysettings):
    """ Create a Client user in the Account.

    Args:
    dict json token acquired from authenticate function
    string email - email address of the new user
    string firstname - firsty name of the new user
    string lastname - last name of the new user
    string company - company of the new user
    string clientpassword - password of the new user
    boolean canresetpassword - user preference to allow user to reset password
    boolean canviewmysettings - user preference to all user to view 'My Settings' """


    uri_path = '/sf/v3/Users'
    print('POST %s%s'%(get_hostname(token), uri_path))
    client = {'Email':email, 'FirstName':firstname, 'LastName':lastname, 'Company':company,
              'Password':clientpassword, 'Preferences':{'CanResetPassword':canresetpassword, 'CanViewMySettings':canviewmysettings}}
    headers = get_authorization_header(token)
    headers['Content-type'] = 'application/json'
    http = httplib.HTTPSConnection(get_hostname(token))
    http.request('POST', uri_path, json.dumps(client), headers=headers)
    response = http.getresponse()

    print(response.status, response.reason)
    new_client = json.loads(response.read().decode('utf-8'))
    print('Created Client %s'%(new_client['Id']))

    http.close()


def create_share_link(token, item_id, req_user_info,filename):
    uri_path = '/sf/v3/Shares?notify=false '
    print('GET %s%s'%(get_hostname(token), uri_path))

    params={
    "ShareType":"Send",
    "Title":filename,
    "Items": [{"Id":item_id}],
    "Recipients":[],
    "ExpirationDate": "2015-06-16",
    "RequireLogin":'false',
    "RequireUserInfo":'true',
    "MaxDownloads": -1,
    "UsesStreamIDs": 'false'
        }

    header=get_authorization_header(token)
    url="https://"+hostname+uri_path
    response = requests.post(url,json=params,headers=header,verify=False)
    out = response.json()['Uri']
    return(out)





if __name__ == '__main__':
    hostname = "hostname.sharefile.com"
    # Leave UN and PW for now, best practice is to create an API/python only account.
    username = "user"
    password = "password"
    client_id = "client_id"
    client_secret = "client_secret"



    sharefile_base_path = '/remote/path'
    report_path = 'C:\local_reports'

    token = authenticate(hostname, client_id, client_secret, username, password)
    if token:
        print(get_root(token,True))

        #Return Dict of Subfolders in Orgs w/key 'Name' and val 'Id'.
        #Hard coded folder id below is relative root directory.
        sharefile_folder_list = get_folder_with_query_parameters(token,'folder_id')
        folders = {}
        missing = []
        for item in sharefile_folder_list:
            folders[item['Name']] = item['Id']

        print(folders.__len__())
        for org in folders.keys():
            time.sleep(5)
            cleaned = ''.join(c for c in org if c.isalnum())
            print(cleaned)
            try:
                file_path = report_path + '\\' + glob.glob1(report_path,cleaned+"*.pdf")[0]
            except IndexError:
                missing.append(org)
                continue
            upload_file(token,str(folders[org]),file_path)

        print(missing)
        print('Number Missing from Upload:'+ str(missing.__len__()) )

        #Get new uploaded file IDs by path...
        sharefile_links_file=''.join([report_path,'\\sharefile_links.csv'])
        writer=csv.writer(open(sharefile_links_file,'w',newline=''))
        #headers
        writer.writerow(['Org','Sharefile Path','File Name','Link'])

        for org in folders.keys():
            cleaned = ''.join(c for c in org if c.isalnum())
            try:
                local_file_name = glob.glob1(report_path,cleaned+"*.pdf")[0]
                share_path = sharefile_base_path + org + '/' + local_file_name
            except IndexError:
                missing.append(org)
                continue
            item_id = get_item_by_path(token, share_path)

            req_user_info=True
            share_link = create_share_link(token,item_id,req_user_info,local_file_name)
            writer.writerow([org,share_path,local_file_name,share_link])

        print(missing)
        print('Number Missing:'+ str(missing.__len__()))
