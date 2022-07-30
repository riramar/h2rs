# -*- coding: utf-8 -*-

"""h2rs.h2rs: provides entry point main()."""

__version__ = '0.0.1'

import base64
import sys
import socket
import ssl
import certifi
import h2.connection
import h2.events
from h2.exceptions import InvalidBodyLengthError
import argparse

def request(request_headers, request_body):
	# generic socket and ssl configuration
	socket.setdefaulttimeout(timeout)
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	ctx.set_alpn_protocols(['h2'])

	try:
		# open a socket to the server and initiate TLS/SSL
		s = socket.create_connection((hostname, tlsport))
		s = ctx.wrap_socket(s, server_hostname=hostname)

		# open the h2 connection
		config = h2.config.H2Configuration(validate_outbound_headers=False, normalize_outbound_headers=False)
		c = h2.connection.H2Connection(config=config)
		c.initiate_connection()
		s.sendall(c.data_to_send())

		# send request headers and body
		c.send_headers(1, request_headers)
		c.send_data(1, request_body, end_stream=True)
		s.sendall(c.data_to_send())

		body = b''
		response_stream_ended = False
		while not response_stream_ended:
			try:
				# read raw data from the socket
				data = s.recv(65536 * 1024)
			except socket.timeout:
				socket_timeout = True
				break

			if not data:
				break

			# feed raw data into h2, and process resulting events
			try:
				events = c.receive_data(data)
			except InvalidBodyLengthError as e:
				error_code = 'InvalidBodyLengthError'
			except:
				error_code = 'Error'
			for event in events:
				if isinstance(event, h2.events.ConnectionTerminated):
					error_code = event.error_code
				elif isinstance(event, h2.events.ResponseReceived):
					response_headers = event.headers
				elif isinstance(event, h2.events.DataReceived):
					# update flow control so the server doesn't starve us
					c.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
					# more response body data received
					body += event.data
				elif isinstance(event, h2.events.StreamEnded):
					# response body completed, let's exit the loop
					response_body = body
					response_stream_ended = True
					break

			# send any pending data to the server
			s.sendall(c.data_to_send())

		# tell the server we are closing the h2 connection
		c.close_connection()
		s.sendall(c.data_to_send())
		# close the socket
		s.close()
	except socket.timeout:
		socket_timeout = True

	if 'response_headers' not in locals():
		response_headers = ''
	if 'response_body' not in locals():
		response_body = ''
	if 'error_code' not in locals():
		error_code = ''
	if 'socket_timeout' not in locals():
		socket_timeout = False

	return {'response_headers':response_headers,'response_body':response_body,'error_code':error_code, 'socket_timeout':socket_timeout}


def h2cl_detect():
	request_headers = [
		(':scheme', 'https'),
		(':method', 'POST'),
		(':path', '/'),
		(':authority', hostname),
		('user-agent', user_agent),
		('content-length', '0'),
	]
	request_body = b''

	response1 = request(request_headers, request_body)

	request_headers[5] = ('content-length', '99999')

	response2 = request(request_headers, request_body)

	request_headers[5] = ('content-length', 'z')

	response3 = request(request_headers, request_body)

	if response1['socket_timeout'] == False and response2['socket_timeout'] == True and (str(response3['error_code']) == 'ErrorCodes.INTERNAL_ERROR' or response3['response_headers'][0][1] == b'400'):
		return True
	else:
		return False


def h2clcrlf_detect():
	request_headers = [
		(':scheme', 'https'),
		(':method', 'POST'),
		(':path', '/'),
		(':authority', hostname),
		('user-agent', user_agent),
		('x', 'x\r\ncontent-length: 0\r\n\r\n'),
	]
	request_body = b''

	response1 = request(request_headers, request_body)

	request_headers[5] = ('x', 'x\r\ncontent-length: 99999\r\n\r\n')
	
	response2 = request(request_headers, request_body)

	if response1['socket_timeout'] == False and response2['socket_timeout'] == True:
		return True
	else:
		return False


def h2te_detect():
	request_headers = [
		(':scheme', 'https'),
		(':method', 'POST'),
		(':path', '/'),
		(':authority', hostname),
		('user-agent', user_agent),
		('content-length', '5'),
		('transfer-encoding', 'chunked'),
	]
	request_body = b'0\r\n\r\n'

	response1 = request(request_headers, request_body)

	request_headers[5] = ('content-length', '9')
	request_body = b'99999\r\n\r\n'

	response2 = request(request_headers, request_body)

	if response1['socket_timeout'] == False and response2['socket_timeout'] == True:
		return True
	else:
		return False


def h2tecrlf_detect():
	request_headers = [
		(':scheme', 'https'),
		(':method', 'POST'),
		(':path', '/'),
		(':authority', hostname),
		('user-agent', user_agent),
		('x', 'x\r\ntransfer-encoding: chunked'),
	]
	request_body = b'0\r\n\r\n'
	
	response1 = request(request_headers, request_body)

	request_body = b'99999\r\n\r\n'
	
	response2 = request(request_headers, request_body)

	if response1['socket_timeout'] == False and response2['socket_timeout'] == True:
		return True
	else:
		return False


def h2tunnel_detect():
	request_headers = [
		(':scheme', 'https'),
		(':method', 'HEAD'),
		(':path', '/'),
		(':authority', hostname),
		('user-agent', user_agent),
		('x: x\r\n\r\nGET / HTTP/1.1\r\nHost: ' + hostname + '\r\n\r\n', 'x'),
	]
	request_body = b''
	
	response = request(request_headers, request_body)

	if response['error_code'] == 'InvalidBodyLengthError':
		return True

	request_headers = [
		(':scheme', 'https'),
		(':method', 'HEAD'),
		(':path', '/ HTTP/1.1\r\nHost: ' + hostname + '\r\n\r\nGET / HTTP/1.1\r\nX: X'),
		(':authority', hostname),
		('user-agent', user_agent),
	]
	request_body = b''
	
	response = request(request_headers, request_body)

	if response['error_code'] == 'InvalidBodyLengthError':
		return True
	else:
		return False


def detect():
	print('Detecting H2.CL request smuggling ...')
	h2cl = h2cl_detect()
	if h2cl == True:
		print('[!] Potencial vulnerable to H2.CL request smuggling.')
	else:
		print('Not potencial vulnerable to H2.CL request smuggling.')
	
	print('Detecting H2.CL (CRLF) request smuggling ...')
	h2clcrlf = h2clcrlf_detect()
	if h2clcrlf == True:
		print('[!] Potencial vulnerable to H2.CL (CRLF) request smuggling.')
	else:
		print('Not potencial vulnerable to H2.CL (CRLF) request smuggling.')

	print('Detecting H2.TE request smuggling ...')
	h2te = h2te_detect()
	if h2te == True:
		print('[!] Potencial vulnerable to H2.TE request smuggling.')
	else:
		print('Not potencial vulnerable to H2.TE request smuggling.')

	print('Detecting H2.TE (CRLF) request smuggling ...')
	h2tecrlf = h2tecrlf_detect()
	if h2tecrlf == True:
		print('[!] Potencial vulnerable to H2.TE (CRLF) request smuggling.')
	else:
		print('Not potencial vulnerable to H2.TE (CRLF) request smuggling.')

	print('Detecting HTTP/2 request tunnelling ...')
	h2tunnel = h2tunnel_detect()
	if h2tunnel == True:
		print('[!] Potencial vulnerable to HTTP/2 request tunnelling.')
	else:
		print('Not potencial vulnerable to HTTP/2 request tunnelling.')

	return


def check():
	request_headers = [
		(':scheme', 'https'),
		(':method', 'GET'),
		(':path', '/'),
		(':authority', hostname),
		('user-agent', user_agent),
	]
	request_body = b''

	print('Making a GET HTTP2 request to ' + hostname + ':' + str(tlsport) + ' ...')
	response = request(request_headers, request_body)
	if response['response_headers'] == '':
		print('Unable to make a GET HTTP2 request to ' + hostname + ':' + str(tlsport) + '.')
		sys.exit(1)
	else:
		print('Got response status code ' + str(response['response_headers'][0][1].decode('UTF-8')) + '.')
		return


def main():
	if sys.version_info < (3, 0):
		print("Error: requires Python 3.x.")
		sys.exit(1)

	global banner, hostname, tlsport, timeout, user_agent
	
	banner = 'IF8gICBfX18gICAgICAgICANCnwgfF98XyAgfF9fXyBfX18gDQp8ICAgfCAgX3wgIF98XyAtfA0KfF98X3xfX198X3wgfF9fX3wNCg=='
	print(base64.b64decode(banner).decode('UTF-8'))
	print('version ' + __version__)

	parser = argparse.ArgumentParser(prog='h2rs', description='Detects request smuggling via HTTP/2 downgrades.')
	parser.add_argument('-t', '--target', help='Target server hostname (eg. www.example.com).')
	parser.add_argument('-p', '--port', type=int, default=443, help='Server TCP port to connect over TLS (default 443).')
	parser.add_argument('-m', '--timeout', type=int, default=5, help='Set connection timeout for request smuggling test (default 5).')
	parser.add_argument('-u', '--user_agent', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36', help='Set default User-Agent request header (default "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36").')
	args = parser.parse_args()

	if args.target:
		hostname = args.target
	else:
		print("Error: requires target parameter.")
		parser.print_help()
		sys.exit(1)

	tlsport = args.port
	timeout = args.timeout
	user_agent = args.user_agent

	check()

	detect()
