from ast import Call
from collections.abc import Callable
from enum import Enum
from http.server import BaseHTTPRequestHandler, HTTPServer
from mimetypes import MimeTypes
from random import choice
from typing import Any, Iterable
from threading import Thread

import os
import time
import json
import hashlib
import dotenv
import socket
import base64

dotenv.load_dotenv()

hostName = "0.0.0.0"
serverPort = 8080

## Cookie Stuff
EXPIRYTIME = 60 * 60 * 24 * 7 * 3 # 3 weeks in seconds
ALLOWEDCHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
STRINGLEN = 10

## Passwords
SALT_STR = os.getenv("SALT")
if SALT_STR == None :
	print("'SALT' env variable not found")
	exit(1)
SALT = int(SALT_STR)

## Socket Server
SOCKET_HOST = "0.0.0.0"
SOCKET_PORT = 9090
MAX_CONENCTED_SOCKET = 1000

class Response:
	def __init__(self) -> None:
		self.status_code: int = -1
		self.headers: list[tuple[str, str]] = []
		self.content: bytes = b""

	def setStatus(self, code: int) :
		self.status_code = code
		return self

	def addHeader(self, name: str, value: str) :
		self.headers.append((name, value))
		return self

	def write(self, what: str | bytes) :
		if type(what) is str :
			self.content += bytes(what, "utf-8")
		elif type(what) is bytes :
			self.content += what
		return self

	def setType(self, tp: str) :
		self.addHeader("Content-Type", tp)
		return self

	@staticmethod
	def Success() :
		return Response().setStatus(200)

	@staticmethod
	def NotFound() :
		return Response().setStatus(404)

	@staticmethod
	def BadRequest() :
		return Response().setStatus(400)

	@staticmethod
	def Unauthorized() :
		return Response().setStatus(401)

	@staticmethod
	def SeeOther() :
		return Response().setStatus(303)

class TokenPermissions(Enum) :
	AccessPrivate = 0

def getTokenString() :
	s = "".join(choice(ALLOWEDCHARS) for _ in range(STRINGLEN))

	if any(x.string == s for x in activeTokens) :
		return getTokenString()

	return s

class Ranks(Enum) :
	Bronze = 0
	Silver = 1
	Gold = 2
	Diamond = 3
	Ruby = 4
	Emerald = 5
	Master = 6

class User :
	def __init__(self, name: str, passw: str) -> None:
		self.name = name
		self.display = name
		self.passw =  hashlib.sha256(passw.encode()+(SALT).to_bytes(), usedforsecurity=True).hexdigest()

		self.uid = len(users)

		self.points = 0
		self.rank = Ranks.Bronze

		users.append(self)

	def dumpJson(self) :
		return {
			"name": self.name,
			"display": self.display,
			"passw": self.passw,
			"uid": self.uid,
			"points": self.points,
			"rank": self.rank.name
		}

	def loadJson(self, json: dict) :
		self.name = json["name"]
		self.display = json["display"]
		self.passw = json["passw"]
		self.uid = json["uid"]
		self.points = json["points"]
		self.rank = [x for x in Ranks if x.name == json["rank"]][0]

	def dumpPublicInfo(self) :
		return {
			"name": self.name,
			"display": self.display,
			"points": self.points,
			"rank": self.rank.name
		}

class Token :
	def __init__(self, user: User) -> None:
		self.permissions: list[TokenPermissions] = []
		self.expiresAt: float = time.time() + EXPIRYTIME
		self.string = getTokenString()
		self.user = user

		activeTokens.append(self)

	@property
	def isExpired(self) :
		return time.time() > self.expiresAt

	def hasPermission(self, perm: TokenPermissions) :
		return perm in self.permissions

	def givePermission(self, perm: TokenPermissions) :
		self.permissions.append(perm)

class Pageinfo :
	def __init__(self, fn: Callable[..., Response], perms: list[TokenPermissions], fallback: str | None = None) -> None:
		self.resolver = fn
		self.perms = perms
		self.fallback = fallback

class MyServer(BaseHTTPRequestHandler):
	def __init__(self, request, client_address, server) -> None:
		self.params: dict[str, str] = {}
		super().__init__(request, client_address, server)

	def sendResponse(self, resp: Response) :
		self.send_response(resp.status_code)

		for i in resp.headers :
			self.send_header(i[0], i[1])

		self.end_headers()

		self.wfile.write(resp.content)

	def getPath(self) :
		return self.path[:self.path.find("?")] if "?" in self.path else self.path

	def getBody(self) :
		body = {}

		for i in self.headers :
			if i == "Content-Length" :
				raw = self.rfile.read(int(self.headers["Content-Length"])).decode()

				body = json.loads(raw)

		if not "?" in self.path :
			return body

		raw = self.path[self.path.find("?")+1:]

		for i in raw.split("&") :
			if not "=" in i :
				body[i] = None
				continue

			k, _, v = i.partition("=")

			body[k] = v

		return body

	def getToken(self) :
		for i in self.headers :
			if i == "Cookie" :
				c = self.headers[i]

				k, _, v = c.partition("=")

				if k == "token" :
					for t in activeTokens :
						if t.string == v :
							return t

		return None

	def captureParams(self, path: str) :
		s_req = self.path.split("/")
		s_path = path.split("/")

		self.params = {}

		for r,p in zip(s_req, s_path) :
			if p.startswith(":") :
				self.params[p.removeprefix(":")] = r

	def matchPath(self, paths: Iterable[str]) :
		split_path = self.path.split("/")

		for i in paths :
			s = i.split("/")

			if len(split_path) != len(s) :
				continue

			if all(split_path[x] == s[x] or s[x].startswith(":") for x in range(len(split_path))) :
				self.captureParams(i)

				return i

		return None

	def handleRequest(self, paths: dict[str, Pageinfo]) :
		path = self.matchPath(paths)

		if path == None :
			with open("notfound.html") as f :
				content = f.read()

			self.sendResponse(
				Response.NotFound().setType("text/html").write(content)
			)

			return

		token = self.getToken()

		info = paths[path]
		hasAccess = len(info.perms) == 0 or (token != None and all(token.hasPermission(x) for x in info.perms))

		if not hasAccess :
			if info.fallback :
				r = Response.SeeOther().addHeader("Location", info.fallback)

				self.sendResponse(r)
				return

			with open("unauthorized.html") as f :
				content = f.read()

			self.sendResponse(Response.Unauthorized().setType("text/html").write(content))
			return

		argnum = info.resolver.__code__.co_argcount

		if argnum == 1 :
			# Pass the reqeust to the resolver
			self.sendResponse(info.resolver(self))
		else :
			self.sendResponse(info.resolver())

	def do_GET(self):
		self.handleRequest(getPaths)

	def do_POST(self):
		self.handleRequest(postPaths)

getPaths: dict[str, Pageinfo] = {}
postPaths: dict[str, Pageinfo] = {}

def exposeFileGet(path: str, *, override_path: str | None = None, override_type: str | None = None, required_perms: list[TokenPermissions] = [], fallback: str | None = None) :
	p = override_path if override_path != None else path

	if not os.path.exists(path) :
		print(f"File not found {repr(path)}")

	tp = "text/html" if override_type == None else override_type

	def inner() :
		with open(path) as f :
			cont = f.read()

		return Response.Success().setType(tp).write(cont)

	exposeFuncGet(p, inner, required_perms=required_perms, fallback=fallback)

def exposeFuncGet(path: str, func: Callable[..., Response], *, required_perms: list[TokenPermissions] = [], fallback: str | None = None) :
	getPaths[path] = Pageinfo(func, required_perms, fallback)

def exposeFuncPost(path: str, func: Callable[..., Response], *, required_perms: list[TokenPermissions] = [], fallback: str | None = None) :
	postPaths[path] = Pageinfo(func, required_perms, fallback)

users: list[User] = []
activeTokens: list[Token] = []

def registerUser(req: MyServer) -> Response :
	body = req.getBody()

	if not "uname" in body or body["uname"] == "" :
		return Response.BadRequest().write("Missing username")

	if not "pass" in body or body["pass"] == "" :
		return Response.BadRequest().write("Missing password")

	for i in users :
		if i.name == body["uname"] :
			return Response.BadRequest().write("Username already in use")

	u = User(body["uname"], body["pass"])

	with open("users.json", "w") as f :
		json.dump([
			x.dumpJson() for x in users
		], f)

	return Response.Success()

def loginUser(req: MyServer) -> Response :
	body = req.getBody()

	if not "uname" in body or body["uname"] == "" :
		return Response.BadRequest().write("Missing username")

	if not "pass" in body or body["pass"] == "" :
		return Response.BadRequest().write("Missing password")

	for i in users :
		if i.name == body["uname"] and i.passw == hashlib.sha256(body["pass"].encode()+(SALT).to_bytes(), usedforsecurity=True).hexdigest() :
			t = Token(i)
			t.givePermission(TokenPermissions.AccessPrivate)

			r = Response.Success()
			r.addHeader("Set-Cookie", f"token={t.string}; HttpOnly; Max-Age={EXPIRYTIME}")
			r.write("/")
			return r

	return Response.BadRequest().write("Invalid credentials")

def traverseJson(obj: dict | list, path: str) :
	where: list[int | str] = [""]

	isint = False

	for i in path :
		if i == "]" : continue

		if (i == "." or i == "[") and isint :
			where[-1] = int(where[-1])
			isint = False

		if i == "." :
			where.append("")
		elif i == "[" :
			isint = True
			where.append("")
		elif type(where[-1]) is str :
			where[-1] += i

	if isint :
		where[-1] = int(where[-1])

	n: Any = obj

	try :
		for i in where :
			n = n[i]
	except (IndexError, KeyError) :
		return None

	return n

def findNth(haystack: str, needle: str, n: int):
    start = haystack.find(needle)
    while start >= 0 and n > 1:
        start = haystack.find(needle, start+1)
        n -= 1
    return start

def fillPattern(pattern: str, info: dict) :
	n_pat = pattern.replace("\t", " ").replace("\n", " ")
	s_pat = [x for x in n_pat.split(" ") if x]

	if len(s_pat) >= 4 and s_pat[-4] == "for" :
		l_space = findNth(n_pat, " ", n_pat.count(" ")-3)
		rep = n_pat[:l_space].strip()

		name = s_pat[-3]
		inside = s_pat[-1]

		over = traverseJson(info, inside)

		val = ""

		if not "," in name :
			if not type(over) is list :
				return ""

			for i in over :
				info[name] = i
				val += fillTemplate(rep, info)
		else :
			k_name, v_name = name.split(",")[0],name.split(",")[1]

			if not type(over) is dict :
				return ""

			for i in over :
				info[k_name] = i
				info[v_name] = over[i]
				val += fillTemplate(rep, info)

		return val

	if len(s_pat) >= 2 and s_pat[-2] == "if" :
		l_space = findNth(n_pat, " ", n_pat.count(" ")-1)
		disp = n_pat[:l_space].strip()

		name = s_pat[-1]
		invert = name.startswith("!")

		over = name.removeprefix("!") if invert else name

		val = traverseJson(info, over)

		if not type(val) is bool :
			return ""

		if val != invert :
			return fillTemplate(disp, info)
		else :
			return ""

	return traverseJson(info, n_pat)

def fillTemplate(temp: str, info: dict) :
	new = ""

	chars = (x for x in temp)

	try :
		while True :
			c = next(chars)

			if c != "$" :
				new += c
				continue

			nx = next(chars)

			if nx != "{" :
				new += nx
				continue

			depth = 1
			pattern = ""

			while depth > 0 :
				n = next(chars)

				pattern += n

				if n == "{" : depth += 1
				if n == "}" : depth -= 1

			pattern = pattern.removesuffix("}").strip()

			val = fillPattern(pattern, info)

			new += str(val)

	except StopIteration :
		...

	return new

def profilePage(req: MyServer) :
	userinfo = None

	for i in users :
		if i.name == req.params["username"] :
			userinfo = i.dumpPublicInfo()
			break

	with open("client/profilepage.html") as f :
		content = fillTemplate(f.read(), {
			"user": userinfo
		})

	return Response.Success().write(content)

def websocket_handshake(conn):
    headers = conn.recv(1024).decode()
    key = ""
    for line in headers.split("\r\n"):
        if line.lower().startswith("sec-websocket-key"):
            key = line.split(":", 1)[1].strip()
            break
    accept_val = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept_val}\r\n"
        "\r\n"
    )
    conn.send(response.encode())

def recv_ws_frame(conn):
    # Get first two bytes
    b1, b2 = conn.recv(2)
    length = b2 & 0x7F
    if length == 126:
        length = int.from_bytes(conn.recv(2), "big")
    elif length == 127:
        length = int.from_bytes(conn.recv(8), "big")
    mask = conn.recv(4)
    data = conn.recv(length)
    return bytes(b ^ mask[i % 4] for i, b in enumerate(data)).decode(errors="ignore")

def send_ws_frame(conn, message):
    payload = message.encode()
    frame = bytearray([0x81])  # FIN + text
    length = len(payload)
    if length <= 125:
        frame.append(length)
    elif length <= 65535:
        frame.append(126)
        frame.extend(length.to_bytes(2, "big"))
    else:
        frame.append(127)
        frame.extend(length.to_bytes(8, "big"))
    frame.extend(payload)
    conn.send(frame)

class SocketClient(Thread) :
	def __init__(self, host: str, port: int, user: User, *, on_msg: Callable[[str], None]) -> None:
		super().__init__(
			target=self.getConnection
		)

		self.start()

		self.on_msg = on_msg

		self.send_queue: list[str] = []

		self.user = user

		self.host = host
		self.port = port

		self.running = True

		self.recvThread: Thread | None = None
		self.sendThread: Thread | None = None

		self.connection: socket.socket | None = None

	def send(self, msg: str) :
		self.send_queue.append(msg)

	def sendMsgThread(self, conn: socket.socket) :
		while self.running :
			if len(self.send_queue) == 0 :
				continue

			m = self.send_queue.pop(0)

			send_ws_frame(conn, m)

	def recvMsgThread(self, conn: socket.socket) :
		while self.running :
			self.on_msg(recv_ws_frame(conn))

	def getConnection(self) :
		print("Started new websocket")

		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			s.bind((self.host, self.port))
			s.listen()
			s.settimeout(5)

			try :
				conn, addr = s.accept()
			except socket.timeout :
				print("Socket timed out!")
				self.stop()
				return

			print(f"Connected to {repr(addr)}")

			websocket_handshake(conn)

			self.connection = conn

			print("Start recvThread")
			self.recvThread = Thread(target=self.recvMsgThread, args=(conn,))
			self.recvThread.start()

			print("Start sendThread")
			self.sendThread = Thread(target=self.sendMsgThread, args=(conn,))
			self.sendThread.start()

	def stop(self) :
		self.running = False

		if self.connection : self.connection.close()

		print("Stopping send subthread")
		if self.sendThread : self.sendThread.join()
		print("Stopping recv subthread")
		if self.recvThread : self.recvThread.join()

class SocketServer(Thread) :
	def __init__(self, host: str, port: int) -> None:
		super().__init__(
			target=self.awaitSockets
		)

		self.host = host
		self.port = port

		self.sockets: list[SocketClient] = []

		self.running = True

	def onMsgRecv(self, msg: str) :
		print(f"Recieved message: {repr(msg)}")

	def requestPort(self, user: User) :
		self.sockets = [x for x in self.sockets if x.running]

		for i in self.sockets :
			if i.user == user :
				return i

		if len(self.sockets) >= MAX_CONENCTED_SOCKET :
			return None

		c = SocketClient(self.host, self.port + len(self.sockets), user, on_msg=self.onMsgRecv)

		self.sockets.append(c)

		return c

	def awaitSockets(self) :
		while self.running :
			pass

		for i in self.sockets :
			print(f"Stopping {repr(i.name)}")
			i.stop()
			i.join()

	def stop(self) :
		self.running = False

def getWebsocket(req: MyServer) :
	tkn = req.getToken()

	if not tkn :
		return Response.Unauthorized()

	user = tkn.user

	socket = socketServer.requestPort(user)

	if not socket :
		return Response.BadRequest().setType("application/json").write('{"success": false}')

	return Response.Success().setType("application/json").write(f'{{"success": true, "port": {socket.port}}}')

if __name__ == "__main__":
	print("Loading users...")

	with open("users.json") as f :
		temp_users = json.load(f)

	for i in temp_users :
		u = User("", "") # Temporary user
		u.loadJson(i)

	webServer = HTTPServer((hostName, serverPort), MyServer)
	print("Web server started http://%s:%s" % (hostName, serverPort))
	socketServer = SocketServer(SOCKET_HOST, SOCKET_PORT)
	socketServer.start()
	print("Socket server started http://%s:%s" % (SOCKET_HOST, SOCKET_PORT))

	exposeFileGet("client/homepage.html", override_path="/login")
	exposeFileGet("client/homepage.js", override_path="/homepage.js", override_type="text/javascript")
	exposeFileGet("client/homepage.css", override_path="/homepage.css", override_type="text/css")

	exposeFileGet("client/personal.html", override_path="/", required_perms=[TokenPermissions.AccessPrivate], fallback="/login")
	exposeFileGet("client/personal.js", override_path="/personal.js", required_perms=[TokenPermissions.AccessPrivate], override_type="text/javascript")

	exposeFuncGet("/user/:username", profilePage)

	exposeFuncGet("/ws", getWebsocket, required_perms=[TokenPermissions.AccessPrivate])

	exposeFuncPost("/register", registerUser)
	exposeFuncPost("/login", loginUser)

	try:
		webServer.serve_forever()
	except KeyboardInterrupt:
		print()

	webServer.server_close()
	print("Web server stopped.")
	print("Stopping socket server")

	socketServer.stop()
	socketServer.join()
	print("Socket server stopped")
