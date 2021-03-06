# -*- coding: utf-8 -*-
from gevent import monkey; monkey.patch_all()
import os
import re
import sys
reload(sys)
sys.setdefaultencoding('utf8')
import cookielib
import urllib
import urllib2
import json
import requests
requests.packages.urllib3.disable_warnings()
from gevent.pywsgi import WSGIServer
from flask import Flask, Response, request, jsonify, abort, render_template, redirect
import functools
import ssl
from urllib import quote_plus, unquote_plus
from requests import session
try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs
from urlparse import urlparse
from pathlib import Path
import subprocess
import platform
import socket
import youtube_dl
old_init = ssl.SSLSocket.__init__

@functools.wraps(old_init)
def ubuntu_openssl_bug_965371(self, *args, **kwargs):
  kwargs['ssl_version'] = ssl.PROTOCOL_TLSv1
  old_init(self, *args, **kwargs)

ssl.SSLSocket.__init__ = ubuntu_openssl_bug_965371

app = Flask(__name__)

config = {
    'tunerCount': 6,  # number of tuners
    'chunkSize': 1024*1024
}

# LINUX/WINDOWS/OSX
if platform.system() == 'Linux':
	FFMPEGLOC = '/usr/bin/ffmpeg'

elif platform.system() == 'Windows':
	FFMPEGLOC = os.path.join('C:\FFMPEG', 'bin', 'ffmpeg.exe')

elif platform.system() == 'Darwin':
	FFMPEGLOC = '/usr/local/bin/ffmpeg'
else:
	log("Unknown OS detected... proxy may not function correctly")

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
        IP = 'http://' + IP
    return IP

discoverData = {
    'FriendlyName': 'illicoTuner',
    'Manufacturer' : 'Videotron',
    'ModelNumber': 'illicoWeb',
    'FirmwareName': 'illico_cable',
    'TunerCount': int(config['tunerCount']),
    'FirmwareVersion': '20150826',
    'DeviceID': '87654321',
    'DeviceAuth': '44563690',
    'BaseURL': '%s' % get_ip(),
    'LineupURL': '%s/lineup.json' % get_ip()
}

#COOKIE = os.path.join('', 'cookie')
user_config_dir = os.path.expanduser("~") + "/.illicoTuner"
if not os.path.isdir(user_config_dir):
    os.makedirs(user_config_dir, 0755)
COOKIE = user_config_dir + "/cookie"
CREDENTIALS = user_config_dir + "/credentials.json"
ILLICOTUNER = user_config_dir + "/illicoTuner.json"
ILLICOM3U = user_config_dir + "/illico.m3u"
BASEURL = get_ip()
COOKIE_JAR = cookielib.LWPCookieJar(COOKIE)
DEBUG = 'true'
PROXYPORT = 5024
URLHOST = get_ip() + ":" + str(PROXYPORT)

def log(string):
	if DEBUG == 'true':
		print("[illicoTuner]: %s" %(string))

def sessionCheck():
    log('SessionCheck: In progress...')


    headers = {'User-agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:19.0) Gecko/20100101 Firefox/19.0',
               'Referer' : 'http://illicoweb.videotron.com',
               'Accept' : 'application/json, text/plain, */*;version=1.1'}

    url = 'https://illicoweb.videotron.com/illicoservice/sessioncheck'

    with session() as c:
        c.cookies = COOKIE_JAR
        try:
            c.cookies.load(ignore_discard=True)
        except:
            c.cookies.save(ignore_discard=True)
        r = c.get(url, headers = headers, verify=False)
        c.cookies.save(ignore_discard=True)
        data = r.text
    
    status = json.loads(data)['head']['userInfo']['clubIllicoStatus']

    if status == 'NOT_CONNECTED':
        log("SessionCheck: NOT CONNECTED.") 
        login()
        return False

    log("SessionCheck: Logged in.")
    return True


def login():
	#log('Login to get cookies!')

	headers = {'User-agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:19.0) Gecko/20100101 Firefox/19.0',
               'Referer' : 'https://illicoweb.videotron.com/accueil',
               'X-Requested-With' : 'XMLHttpRequest',
               'Content-Type' : 'application/json'}

	url = 'https://id.videotron.com/oam/server/authentication'
	credentials_Info = {}
	credentials_File = Path(CREDENTIALS)
	if credentials_File.exists():
		with open(CREDENTIALS,'r') as f:
			credentials_Info = json.load(f)
		USERNAME = credentials_Info['username']
		PASSWORD = credentials_Info['password']
	payload = {
        'username' : USERNAME,
        'password' : PASSWORD,
        'type' : 'EspaceClient-Residentiel',
        'successurl' : 'https://id.videotron.com/vl-sso-bin/login-app-result.pl'
	}
    
	with session() as c:
		c.cookies = COOKIE_JAR
		c.get('http://illicoweb.videotron.com/accueil', verify=False)
		c.cookies.save(ignore_discard=True)
		r = c.post(url, data=payload, headers=headers, verify=False)
		c.cookies.save(ignore_discard=True)

            
def getRequest(url, data=None, headers=None, params=None):
    if (not sessionCheck()):
        login()
    
    #log("Getting requested url: %s" % url)
        
    data, result = getRequestedUrl(url, data, headers, params)

    if (result == 302):
        log("Unauthenticated.  Logging in.")
        COOKIE_JAR.clear()
        COOKIE_JAR.save(COOKIE, ignore_discard=True, ignore_expires=False)

        login()
        data = getRequestedUrl(url, data, headers)
    
    if (result == 403):
        log("Unauthorized content.  Encrypted or for Club Illico Subscribers only")
        return None, result
    
    if data == None:
        log('No response from server')
        
    return (data, result)

def getRequestedUrl(url, data=None, headers=None, params=None):
    if headers is None:
        headers = {'User-agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:19.0) Gecko/20100101 Firefox/19.0',
                   'Referer' : 'http://illicoweb.videotron.com',
                   'Accept' : 'application/json, text/plain, */*;version=1.1'}

    COOKIE_JAR.load(ignore_discard=True)

    with session() as c:
        c.cookies = COOKIE_JAR
        r = c.get(url, params = params, headers = headers, verify=False)
        c.cookies.save(ignore_discard=True)
        data = r.text
        code = r.status_code

    
    if (code == 404):
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(COOKIE_JAR))
        urllib2.install_opener(opener)
        if (not params is None):
            url = url + "?" + params
        req = urllib2.Request(url,data,headers)
        response = urllib2.urlopen(req)
        data = response.read()
        COOKIE_JAR.save(COOKIE, ignore_discard=True, ignore_expires=False)
        response.close()
        #log("getRequest : %s" %url)
        code = response.getcode()
    return (data, code)

def create_lineup():
	lineupTuner = []
	url = 'https://illicoweb.videotron.com/illicoservice/channels/user?localeLang=fr'
	headers = {'User-agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:19.0) Gecko/20100101 Firefox/19.0', 'Referer' : 'https://illicoweb.videotron.com/accueil'}
	values = {}
	jsonData, data = getRequest(url)
	jsonData = (jsonData.encode('utf-8'))
	channels = json.loads(jsonData)['body']['main']
	for channel in channels:
		title = channel['name']
		pid = channel['defaultChannel']
		live = str(channel['hasLinearFeed'])
		if live == 'True':
			log("Get channel: %s" %title)
			urlPid = URLHOST + '/channel/remuxed?pid=' + str(pid)
			lineupTuner.append({'GuideNumber': str(pid), 'GuideName': title, 'URL': urlPid })
	with open(ILLICOTUNER,"w") as f:
		json.dump(lineupTuner, f, ensure_ascii=False)
	return lineupTuner

@app.route('/credentials' , methods=['GET', 'POST'])
def credentials():
	credentials_Info = {}
	if request.method == 'POST':
		USERNAME = request.form.get('username')
		PASSWORD = request.form.get('password')
		credentials_Info = {
							'username' : USERNAME,
							'password' : PASSWORD
							}
		with open(CREDENTIALS,"w") as f:
			json.dump(credentials_Info, f, ensure_ascii=False)
	return '''<form method="POST">
                  Username: <input type="text" name="username"><br>
                  Password: <input type="text" name="password"><br>
                  <input type="submit" value="Submit"><br>
              </form>'''

@app.route('/discover.json')
def discover():
	return jsonify(discoverData)


@app.route('/lineup_status.json')
def status():
    return jsonify({
        'ScanInProgress': 0,
        'ScanPossible': 1,
        'Source': "cable",
        'SourceList': ['Cable']
    })


@app.route('/lineup.json')
def lineup():
	json_File = Path(ILLICOTUNER)
	if not json_File.exists():
		create_lineup()
	with open(ILLICOTUNER,'r') as f:
		json_Lineup = f.read()
	return json_Lineup

@app.route('/lineup.post', methods=['GET', 'POST'])
def lineup_post():
	create_lineup()
	return redirect('/lineup.json')

@app.route('/channel')
def channel():
	pid = request.args.get('pid', default = 1, type = str)
	link_Pid = '/order/channel/' + str(pid)
	#log('link_Pid: %s' % link_Pid)
	channel_Url = get_Live_Url(link_Pid)
	log('channel_Url: %s' % channel_Url)
	return redirect(channel_Url)

@app.route('/channel/remuxed')
def channel_Remuxed():
	pid = request.args.get('pid', default = 1, type = str)
	link_Pid = '/order/channel/' + str(pid)
	channel_Url = get_Live_Url(link_Pid)
	ydl_opts = {
		'format': 'bestaudio/best',
	}
    
	with youtube_dl.YoutubeDL(ydl_opts) as ydl:
		info_dict = ydl.extract_info(channel_Url, download=False)
		video_url = info_dict.get("url", None)
	def generate():
		cmdline = list()
		cmdline.append(FFMPEGLOC)
		cmdline.append("-i")
		cmdline.append(video_url)
		cmdline.append("-vcodec")
		cmdline.append("copy")
		cmdline.append("-acodec")
		cmdline.append("copy")
		cmdline.append("-f")
		cmdline.append("mpegts")
		cmdline.append("pipe:1")
		log(cmdline)
		FNULL = open(os.devnull, 'w')
		proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=FNULL)
		try:
				f = proc.stdout
				byte = f.read(256)
				while byte:
					yield byte
					byte = f.read(256)
		finally:
			proc.kill()


	return Response(response=generate(), status=200, mimetype='video/mp2t',
					headers={'Access-Control-Allow-Origin': '*', "Content-Type": "video/mp2t",
							 "Content-Disposition": "inline", "Content-Transfer-Enconding": "binary"})


@app.route('/M3u.get', methods=['GET', 'POST'])
def create_M3u_List():
	url = 'https://illicoweb.videotron.com/illicoservice/channels/user?localeLang=fr'
	headers = {'User-agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:19.0) Gecko/20100101 Firefox/19.0', 'Referer' : 'https://illicoweb.videotron.com/accueil'}
	values = {}
	jsonData, data = getRequest(url)
	jsonData = (jsonData.encode('utf-8'))
	channels = json.loads(jsonData)['body']['main']
	with open(ILLICOM3U,"w") as f:
		f.write("#EXTM3U" + "\n")
	for channel in channels:
		title = channel['name']
		pid = channel['defaultChannel']
		live = str(channel['hasLinearFeed'])
		if live == 'True':
			log("Get channel: %s" %title)
			Channel_Title = "#EXTINF:-1 tvh-chnum=" + str(pid) + " ," + title
			urlPid = URLHOST + "/channel?pid=" + str(pid)
			with open(ILLICOM3U,"a") as f:
				f.write(Channel_Title + "\n" + urlPid + "\n")
	with open(ILLICOM3U,"r") as f:
		m3u_File = f.read()
	return m3u_File

@app.route('/')
@app.route('/device.xml')
def device():
	return """<root xmlns="urn:schemas-upnp-org:device-1-0">
		<specVersion>
			<major>1</major>
			<minor>0</minor>
		</specVersion>
		<URLBase>{data}</URLBase>
		<device>
			<deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
			<friendlyName>illicoTuner</friendlyName>
			<manufacturer>Videotron</manufacturer>
			<modelName>illicoWeb</modelName>
			<modelNumber>illicoWeb</modelNumber>
			<serialNumber></serialNumber>
			<UDN>uuid:87654321</UDN>
		</device>
	</root>""".format(data = get_ip())
    
    
    #return render_template('device.xml',data = discoverData),{'Content-Type': 'application/xml'}


def get_Live_Url(pid):
	url = 'https://illicoweb.videotron.com/illicoservice'+str(pid)+'?streamType=dash'
	if '?' in url:
		url = url + '&localeLang=fr'
		#log("Live show at: %s" %url)
	headers = {'User-agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:19.0) Gecko/20100101 Firefox/19.0', 'Referer' : 'https://illicoweb.videotron.com/accueil'}
	values = {}
	data, result = getRequest(url,urllib.urlencode(values),headers)
	if result == 403:
		log('Content unavailable... Forbidden')
		return False
            
	options = {'live': '1'}

	if (not data is None) and (result == 200):
		info = json.loads(data)
		path = info['body']['main']['mainToken']        
		final_url = path
		log('final_url: %s' % final_url)
		return final_url
	else:
		log("Failed to get link")
		return False

if __name__ == '__main__':
	http = WSGIServer(('0.0.0.0', PROXYPORT), app.wsgi_app)
	http.serve_forever()

