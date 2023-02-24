# MinimAPI client

JS client for [MinimAPI](https://github.com/minimapi/minimapi)

See usage examples [here](https://github.com/minimapi/minimapi-examples)


## Usage

```js
let client = new MinimAPI(
        API URL, // with ending '/'
        model.json URL // optionnal (using API URL by default)
    )
```

Example :
```html
<script type="text/javascript" src="minimapi-client.js" ></script>
<script>
    let client = new MinimAPI('/api/')
    client.list('users').then(console.log)
</script>
```

