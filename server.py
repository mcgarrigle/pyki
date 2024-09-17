#!/usr/bin/env python3

import http.server, ssl

pkifile='/home/pete/projects/docker-kafka/kafka'
pkifile='secrets/www'

server_address = ('0.0.0.0', 4443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket,
                               server_side=True,
                               keyfile=f"{pkifile}.key",
                               certfile=f"{pkifile}.crt",
                               ssl_version=ssl.PROTOCOL_TLS)
httpd.serve_forever()
