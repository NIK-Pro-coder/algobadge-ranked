## Template Engine
### Value inclusion :
A string like :
```html
<h1>${user.name}</h1>
```
When given the context of
```json
{
	"user": {
		"name": "hello world"
	}
}
```
Will produce the string :
```html
<h1>hello world</h1>
```

### For Loop (Lists)
A string like :
```html
<div>
	${ <p>${i}</p> for i in test }
</div>
```
When given the context of:
```json
{
	"test": ["hi", "hello", "bonjour"]
}
```
Will produce the string :
```html
<div>
	<p>hi</p>
	<p>hello</p>
	<p>bonjour</p>
</div>
```
> [!WARNING]
> This will produce an empty string regardless of template if the value that should be iterated is not a list

### For Loop (Objects)
A string like :
```html
<div>
	${ <a href="${k}">${v}</a><br /> for k,v in dict }
</div>
```
When given the context of:
```json
{
	"dict": {
		"https://link1.com": "user1"
		"https://link2.com": "user2"
		"https://link3.com": "user3"
	}
}
```
Will produce the string :
```html
<div>
	<a href="https://link1.com">user1</a><br />
	<a href="https://link2.com">user2</a><br />
	<a href="https://link3.com">user3</a><br />
</div>
```
> [!WARNING]
> This will produce an empty string regardless of template if the value that should be iterated is not an object

### If Statements
A string like:
```html
${ <p>You are authorized</p> if auth }
${ <p>You are not authorized</p> if !auth }
```
When given the context of:
```json
{
	"auth": true
}
```
Will produce the string:
```html
<p>You are authorized</p>
```
And when given the context of:
```json
{
	"auth": false
}
```
Will produce the string:
```html
<p>You are not authorized</p>
```
> [!WARNING]
> This will produce an empty string regardless of template if the value to check is not a bool

## Gamemode Info

### Player Info
	- Player Number (int)
	- Team Size (optional, int)

### Round Info
	- Round Number (int)
	- Round Duration (int as minutes)

### Tournament Info
	- Tournament (bool)
	- Loser's Bracket (bool)
	- Selection Method (enum: Rank-Based, Round-Robin)

### Modifier Info
	- Modifier (enum: None, Knockout, Points)
