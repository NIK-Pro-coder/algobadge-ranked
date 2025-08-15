from ast import Call
from collections.abc import Callable
from enum import Enum
from http.server import BaseHTTPRequestHandler, HTTPServer
from random import choice

import os
import time
import json
import hashlib
import dotenv

dotenv.load_dotenv()

hostName = "localhost"
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

getPaths: dict[str, Pageinfo] = {}
postPaths: dict[str, Callable[[dict], Response]] = {}

class MyServer(BaseHTTPRequestHandler):
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

	def do_GET(self):
		token = self.getToken()

		for i in getPaths :
			if i == self.getPath() :
				info = getPaths[i]

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
					self.sendResponse(info.resolver(token))
				else :
					self.sendResponse(info.resolver())

				return

		with open("notfound.html") as f :
			content = f.read()

		self.sendResponse(
			Response.NotFound().setType("text/html").write(content)
		)

	def do_POST(self):
		body = self.getBody()

		for i in postPaths :
			if i == self.getPath() :
				self.sendResponse(postPaths[i](body))
				return

		with open("notfound.html") as f :
			content = f.read()

		self.sendResponse(
			Response.NotFound().setType("text/html").write(content)
		)

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

def exposeFuncPost(path: str, func: Callable[[dict], Response]) :
	postPaths[path] = func

users: list[User] = []
activeTokens: list[Token] = []

def registerUser(body: dict) -> Response :
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

def loginUser(body: dict) -> Response :
	if not "uname" in body or body["uname"] == "" :
		return Response.BadRequest().write("Missing username")

	if not "pass" in body or body["pass"] == "" :
		return Response.BadRequest().write("Missing password")

	for i in users :
		if i.name == body["uname"] and i.passw == hashlib.sha256(body["pass"].encode()+(SALT).to_bytes()).hexdigest() :
			t = Token(i)
			t.givePermission(TokenPermissions.AccessPrivate)

			r = Response.Success()
			r.addHeader("Set-Cookie", f"token={t.string}; HttpOnly; Max-Age={EXPIRYTIME}")
			r.write("/")
			return r

	return Response.BadRequest().write("Invalid credentials")

def getUserInfo(token: Token | None) :
	if token == None :
		return Response.BadRequest()

	user = token.user

	body = {
		"name": user.name
	}

	return Response.Success().setType("application/json").write(json.dumps(body))

if __name__ == "__main__":
	print("Loading users...")

	with open("users.json") as f :
		temp_users = json.load(f)

	for i in temp_users :
		u = User("", "") # Temporary user
		u.loadJson(i)

	webServer = HTTPServer((hostName, serverPort), MyServer)
	print("Server started http://%s:%s" % (hostName, serverPort))

	exposeFileGet("client/homepage.html", override_path="/login")
	exposeFileGet("client/homepage.js", override_path="/homepage.js", override_type="text/javascript")
	exposeFileGet("client/homepage.css", override_path="/homepage.css", override_type="text/css")

	exposeFileGet("client/personal.html", override_path="/", required_perms=[TokenPermissions.AccessPrivate], fallback="/login")

	exposeFuncGet("/userinfo", getUserInfo, required_perms=[TokenPermissions.AccessPrivate])

	exposeFuncPost("/register", registerUser)
	exposeFuncPost("/login", loginUser)

	try:
		webServer.serve_forever()
	except KeyboardInterrupt:
		pass

	webServer.server_close()
	print("Server stopped.")
