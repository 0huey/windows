Experiementing with passing arbitrary data in HTTP Cookie headers.

```
GET /test HTTP/1.1
Referer: www.google.com
Accept: text/html, application/xhtml+xml, application/xml
Host: www.google.com
Cookie: NID=dGVzdCBkYXRh; path=/; domain=.google.com; Secure
User-Agent: win32

HTTP/1.0 404 Not Found
Server: BaseHTTP/0.6 Python/3.10.0
Date: Tue, 09 May 2023 02:58:04 GMT
Content-Type: text/html
Set-Cookie: NID=cmV0dXJuaW5nIGNhcGl0YWxpemVkIGRhdGE6IFRFU1QgREFUQQ==
Content-Length: 446

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
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
</html>
```
