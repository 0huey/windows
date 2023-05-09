import http.server
import base64

error_404 = b"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 404</p>
        <p>Message: Not Found.</p>
        <p>Error code explanation: 404 - Nothing matches the given URI.</p>
    </body>
</html>"""

class HttpHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        encoded = None

        cookies = self.headers.get("Cookie").split(";")

        for cook in cookies:
            cook = cook.split("=")
            if len(cook) != 2:
                continue

            name = cook[0]
            value = cook[1]

            if name == "NID":
                decoded = base64.b64decode(value).decode('ascii')
                print("Got data from client:", decoded)

                response = f"~~{decoded.upper()}~~"
                encoded = base64.b64encode(response.encode('ascii')).decode('ascii')
                break

        self.send_response(404)
        self.send_header("Content-Type", "text/html")

        if encoded:
            self.send_header("Set-Cookie", "NID=" + encoded)

        self.send_header("Content-Length", str(len(error_404)))
        self.end_headers()

        self.wfile.write(error_404)

if __name__ == "__main__":
    HOST, PORT = "localhost", 8080
    httpd = http.server.HTTPServer((HOST, PORT), HttpHandler)
    httpd.serve_forever()
