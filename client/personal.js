function sendSocketMsg(msg) {
	socket.send(JSON.stringify(msg));
}

function handleMessage(msg) {
	console.log(`Recieved message: ${JSON.stringify(msg, null, 2)}`);

	if (msg.type === "ping") {
		sendSocketMsg({
			type: "pong",
		});
	}
}

let socket;

async function main() {
	let data = await fetch("/ws");
	let json = await data.json();

	if (!json.success) {
		console.log("womp womp");
		return;
	}

	let port = json.port;

	socket = new WebSocket(`ws://${location.hostname}:${port}`);

	console.log(socket);

	// Connection opened
	socket.addEventListener("open", (event) => {
		console.log("Connected to the SocketServer");
	});

	// Listen for messages
	socket.addEventListener("message", (event) => {
		let msg = JSON.parse(event.data);
		handleMessage(msg);
	});

	let matchmakingButton = document.getElementById("matchmaking");

	matchmakingButton.addEventListener("click", () => {
		sendSocketMsg({
			type: "startMatchmaking",
		});
	});
}

main();

async function logout() {
	let _ = await fetch("/logout", {
		method: "POST",
	});

	window.location.reload();
}
