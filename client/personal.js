function sendSocketMsg(msg) {
	socket.send(JSON.stringify(msg));
}

function handleMessage(msg) {
	if (msg.type === "ping") {
		sendSocketMsg({
			type: "pong",
		});

		return;
	}

	console.log(`Recieved message: ${JSON.stringify(msg, null, 2)}`);

	if (msg.type === "close") {
		console.log("Closing");

		socket.close();

		return;
	}
}

let socket;

async function attemptConnection() {
	let data = await fetch("/ws");
	let json = await data.json();

	if (!json.success) {
		console.log("Failed to connect to SocketServer");
		return false;
	}

	let port = json.port;

	socket = new WebSocket(`ws://${location.hostname}:${port}`);

	return true;
}

async function main() {
	let attempt = 1;

	let before = document.getElementById("beforeSocket");
	let after = document.getElementById("afterSocket");

	let attemptCount = document.getElementById("attemptCount");

	let done = false;

	while (!done) {
		attemptCount.innerHTML = `Attempt ${attempt}`;

		// Sleep for 1000ms
		await new Promise((r) => setTimeout(r, 1000));

		done = await attemptConnection();
		attempt += 1;
	}

	before.hidden = true;
	after.hidden = false;

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
	await fetch("/logout", {
		method: "POST",
	});

	window.location.reload();
}
