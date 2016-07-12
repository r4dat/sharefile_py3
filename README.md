# sharefile_py3
A python 3 program to work with Citrix's Sharefile API.

This is a (mostly) python 3 compatible version of Citrix's published python example with extensions based on their web API.

The program as a whole is designed to upload files in a local directory to folders already created on sharefile, and then create shared URLs which are used in automatic e-mail generation.
E.g. C:\local_reports\OrgAReport20150407.pdf is uploaded resulting in  /Orgs/Org A. Corp/OrgACorpReport20150407.pdf.
We then get the file id by searching the remote sharefile directory and create a DL URL which is output to a file.

One relatively new item is the create_share_link function which creates the URLs. Note they currently have a hard-coded expiration date.

The original (Python 2) source can be found here:
http://api.sharefile.com/rest/samples/python.aspx

Copyright (c) 2014 Citrix Systems, Inc.
under the MIT License.

The python 3 version is licensed under the Apache License 2.0.
Copyright (c) 2015 Rob R, KHC

The functions in this file will make use of the ShareFile API v3 to show some of the basic
operations using GET, POST, PATCH, DELETE HTTP verbs. See api.sharefile.com for more information.
 
Requirements:
 
Although not fully ported, the current version uses both the "standard" http and urlib libraries, as well as the Requests library.
 
Authentication
 
OAuth2 password grant is used for authentication. After the token is acquired it is sent an an
authorization header with subsequent API requests. 
 
Exception / Error Checking:
  
For simplicity, exception handling has not been added.  Code should not be used in a production environment.

