async function main() {
	let data = await fetch("/ws");
	let json = await data.json();

	if (!json.success) {
		console.log("womp womp");
		return;
	}

	let port = json.port;

	const socket = new WebSocket(`ws://${location.hostname}:${port}`);

	// Connection opened
	socket.addEventListener("open", (event) => {
		console.log("Connected to the SocketServer");
	});

	// Listen for messages
	socket.addEventListener("message", (event) => {
		console.log("Message from server ", event.data);
	});
}

main();

async function logout() {
	let _ = await fetch("/logout", {
		method: "POST",
	});

	window.location.reload();
}
