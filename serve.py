import http.server
import functools

class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

handler = functools.partial(NoCacheHandler, directory="/Users/camil/Desktop/APPs/simple-app")
httpd = http.server.ThreadingHTTPServer(("0.0.0.0", 8080), handler)
httpd.serve_forever()
