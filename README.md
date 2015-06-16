# sharefile_py3
A python 3 program to work with Citrix's Sharefile API.

This is a (mostly) python 3 compatible version of Citrix's published python example interacting with their web API.

The original (python 2) source can be found here:
http://api.sharefile.com/rest/samples/python.aspx



"""
Copyright (c) 2014 Citrix Systems, Inc.
 
Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:
 
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
 
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
"""
 
"""
The functions in this file will make use of the ShareFile API v3 to show some of the basic
operations using GET, POST, PATCH, DELETE HTTP verbs. See api.sharefile.com for more information.
 
Requirements:
 
All required libraries should be part of most standard python installations.
 
Functions were tested with python 2.7.1
 
Authentication
 
OAuth2 password grant is used for authentication. After the token is acquired it is sent an an
authorization header with subsequent API requests. 
 
Exception / Error Checking:
  
For simplicity, exception handling has not been added.  Code should not be used in a production environment.
"""
