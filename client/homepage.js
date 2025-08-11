async function attemptRegister() {
	let uname = document.getElementById("register-uname").value;
	let pass = document.getElementById("register-pass").value;

	let data = await fetch("/register", {
		method: "POST",
		body: JSON.stringify({
			uname: uname,
			pass: pass,
		}),
	});
	let reader = data.body.getReader();
	let intarray = await reader.read();
	let msg = new TextDecoder().decode(intarray.value);

	let p = document.getElementById("register-error");

	p.innerHTML = msg;

	if (data.status === 200) {
		document.getElementById("login-uname").value = uname;
		document.getElementById("login-pass").value = pass;

		attemptLogin();
	}
}

async function attemptLogin() {
	let uname = document.getElementById("login-uname").value;
	let pass = document.getElementById("login-pass").value;

	let data = await fetch("/login", {
		method: "POST",
		body: JSON.stringify({
			uname: uname,
			pass: pass,
		}),
	});
	let reader = data.body.getReader();
	let intarray = await reader.read();
	let msg = new TextDecoder().decode(intarray.value);

	let p = document.getElementById("login-error");

	if (data.status === 200) {
		window.location.replace(msg);
	} else {
		p.innerHTML = msg;
	}
}
