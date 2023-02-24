class MinimAPI {
	constructor(api_url, model_url=null){
		this.api_url = api_url
		this.#load_model(model_url || api_url + 'model.json')
	}

	async set_encryption(key){
		this.crypto = new Minimapi_crypto()
		this.crypto.load_key(key)
	}

	list(type){
		return this.#request('GET', this.api_url+type, null, type)
	}

	read(type, id){
		return this.#request('GET', this.api_url+type+'/'+id, null, type)
	}

	search(type, filters){
		return this.#request('GET', this.api_url+type+'?'+new URLSearchParams(filters).toString(), null, type)
	}

	create(type, object){
		return this.#request('POST', this.api_url+type, object, type)
	}

	update(type, id, object){
		delete object.id
		return this.#request('PUT', this.api_url+type+'/'+id, object, type)
	}

	del(type, id){
		return this.#request('DELETE', this.api_url+type+'/'+id, null, type)
	}

	#load_model(model_url){
		const xhr = new XMLHttpRequest()
		xhr.open('GET', model_url, false)
		xhr.send(null)
		if (xhr.status !== 200) {
			return
		}
		let model = JSON.parse(xhr.responseText)
		for(var type in model){
			for(var property in model[type]){
				if(!model[type][property].hasOwnProperty('tags')){
					model[type][property]['tags'] = []
				}
			}
		}
		this.model = model
	}

	async #request(method, path, data=null, data_type=null){

		var that = this

		// Encrypt data to send if defined in model
		if(data && data_type){
			for(var property in data){
				if(this.model[data_type][property].tags.includes('encrypted')){
					data[property] = await this.crypto.encrypt(data[property])
				}
			}
		}

		// Encrypt url param if defined in model
		if(path.includes('?') && data_type){
			var url_param = new URLSearchParams(path.split('?')[1])
			for(const [key, value] of url_param){
				if(this.model[data_type][key].tags.includes('encrypted')){
					url_param.set(key, await this.crypto.encrypt(data[property]))
				}
			}
			path = path.split('?')[0]+'?'+url_param.toString()
		}

		return new Promise(function (resolve, reject) {
			let expected_status = {
				'GET': 200,
				'POST': 201,
				'PUT': 201,
				'DELETE': 204
			}

			var xhr = null
			if(window.XMLHttpRequest){
				xhr = new XMLHttpRequest()
			}else{
				alert('Votre navigateur ne supporte pas les objets XMLHTTPRequest...')
				xhr = false
			}
			xhr.onload = async function(){

				if(xhr.status == expected_status[method]){
					if(xhr.responseText.length){
						var data = JSON.parse(xhr.responseText)

						// Decrypt data if defined in model
						if(data_type){
							for(var element of data){
								for(var property in element){
									if(element[property] && element[property].length > 1 && that.model[data_type].hasOwnProperty(property) && that.model[data_type][property].tags.includes('encrypted')){
										element[property] = await that.crypto.decrypt(element[property])
									}
								}
							}
						}
						resolve(data)
					}else{
						resolve(null)
					}
				}else{
					reject({
						status: xhr.status,
						statusText: xhr.statusText
					});
				}
			}
			xhr.onerror = function () {
				reject({
					status: xhr.status,
					statusText: xhr.statusText
				});
			};
			xhr.open(method, path, true)
			xhr.setRequestHeader('Content-Type', 'application/json')
			xhr.send((data)?JSON.stringify(data):null)
		})
	}
}

class Minimapi_crypto {
	buf2hex(buffer){
		return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('')
	}

	hex2buf(string) {
		return new Uint8Array(string.match(/.{1,2}/g).map(byte => parseInt(byte, 16)))
	}
	
	load_key(key){
		var encoder = new TextEncoder("utf-8")
		return window.crypto.subtle.importKey(
			"raw", //type
			new Uint8Array(encoder.encode(key)),
			'AES-CBC',
			false, //extractable
			["encrypt", "decrypt"]
		).then((key) => {
			this.key = key
		})
	}

	generate_iv(){
		return window.crypto.getRandomValues(new Uint8Array(16))
	}

	encrypt(plaintext){
		var iv = this.generate_iv()
		return window.crypto.subtle.encrypt(
			{
				name: "AES-CBC",
				iv: iv
			},
			this.key,
			new TextEncoder("utf-8").encode(plaintext)
		).then((cipher) => {
			return this.buf2hex(iv)+','+this.buf2hex(cipher)
		})
	}

	decrypt(cipher){
		return window.crypto.subtle.decrypt(
			{
				name: "AES-CBC",
				iv: this.hex2buf(cipher.split(',')[0])
			},
			this.key,
			this.hex2buf(cipher.split(',')[1])
		).then((plain) => {
			return new TextDecoder("utf-8").decode(plain)
		})
	}
}