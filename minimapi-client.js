class MinimAPI {
	constructor(api_url, model_url=null){
		this.api_url = api_url
		this.model_url = (model_url || api_url + 'model.json')
	}

	async set_encryption(secret){
		this.crypto = new MinimAPI_crypto()
		await this.crypto.load_key(secret)
	}

	async change_encryption_key(new_secret){
		await this.crypto.load_new_key(new_secret)
		for(var type in this.model){
			if(Object.values(this.model[type]).filter((t) => t.tags.includes('encrypted')).length){
				let index = await this.list(type)
				let i = 0
				for(let row of index){
					i++
					console.log(`${type} / ${row.id} -> ${i}/${index.length}`)
					let data = await this.read(type, row.id)
					await this.update(type, row.id, data[0])
				}
			}
		}
		await this.crypto.unload_new_key()
		console.log('Done')
	}

	async init(){
		await this.#load_model()
	}

	async auth(auth_class=null, auth_data=null){
		if(auth_class){
			this.auth = new auth_class()
			await this.auth.login(this.api_url, auth_data)
		}
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

	async #load_model(){
		let result = await this.#request('GET', this.model_url)
		let model = result
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
				if(data[property] && this.model[data_type][property].tags.includes('encrypted')){
					data[property] = await this.crypto.encrypt(data[property])
				}
			}
		}

		// Encrypt url param if defined in model
		if(path.includes('?') && data_type){
			var url_param = new URLSearchParams(path.split('?')[1])
			for(const [key, value] of url_param){
				if(value && this.model[data_type][key].tags.includes('encrypted')){
					url_param.set(key, await this.crypto.encrypt(value))
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

						if(method == 'PUT' && that.hasOwnProperty('crypto')){
							if(that.crypto.is_key_change_in_progress()){
								resolve(null)
								return
							}
						}

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
			let data_to_send = (data)?JSON.stringify(data):null
			if('auth' in that && 'get_auth_header' in that.auth){
				that.auth.get_auth_header(method, path, data_to_send).then((header_value) => {
					xhr.setRequestHeader('Authorization', header_value)
					xhr.send((data)?JSON.stringify(data):null)
				})
			}else{
				xhr.send(data_to_send)
			}
		})
	}
}

class MinimAPI_crypto {
	static encryption_algo = 'AES-CBC'

	#buf2hex(buffer){
		return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('')
	}

	#hex2buf(string) {
		return new Uint8Array(string.match(/.{1,2}/g).map(byte => parseInt(byte, 16)))
	}

	async #derive_secret(secret){
		return await window.crypto.subtle.digest(
			{name: "SHA-256"},
			new Uint8Array(new TextEncoder().encode(secret))
		)
	}
	
	async load_key(secret){
		let derived_secret = await this.#derive_secret(secret)
		this.key = await window.crypto.subtle.importKey(
			'raw',
			derived_secret,
			this.constructor.encryption_algo,
			true,
			['encrypt', 'decrypt']
		)
	}

	is_key_change_in_progress(){
		return this.hasOwnProperty('new_key')
	}

	async load_new_key(new_secret){
		let current_key = this.key
		await this.load_key(new_secret)
		this.new_key = this.key
		this.key = current_key
	}

	unload_new_key(){
		this.key = this.new_key
		delete this.new_key
	}

	#generate_iv(){
		return window.crypto.getRandomValues(new Uint8Array(16))
	}

	async encrypt(plaintext){
		let key = this.hasOwnProperty('new_key')?this.new_key:this.key
		let iv = this.#generate_iv()
		let ciphertext = await window.crypto.subtle.encrypt(
			{
				name: this.constructor.encryption_algo,
				iv: iv
			},
			key,
			new TextEncoder('utf-8').encode(plaintext)
		)
		return this.#buf2hex(iv)+','+this.#buf2hex(ciphertext)
	}

	async decrypt(cipher){
		let plaintext = await window.crypto.subtle.decrypt(
			{
				name: this.constructor.encryption_algo,
				iv: this.#hex2buf(cipher.split(',')[0])
			},
			this.key,
			this.#hex2buf(cipher.split(',')[1])
		)
		return new TextDecoder('utf-8').decode(plaintext)
	}
}

class MinimAPI_auth{
	async get_auth_header(method, path, data){
		return ''
	}

	async login(api_url, auth_data){
		let result = await this.request(api_url+'auth', auth_data)
		this.handle_login_result(result)
	}

	handle_login_result(result){}

	async request(path, data=null){
		return new Promise(function (resolve, reject) {
			const xhr = new XMLHttpRequest()
			xhr.onload = async function(){
				if(xhr.status == 200){
					if(xhr.responseText.length){
						resolve(JSON.parse(xhr.responseText))
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
			xhr.open('POST', path, true)
			xhr.setRequestHeader('Content-Type', 'application/json')
			xhr.send((data)?JSON.stringify(data):null)
		})
	}
}

class MinimAPI_auth_token_based extends MinimAPI_auth {
	get_auth_header(method, path, data){
		return this.token
	}
}

class MinimAPI_auth_bearer extends MinimAPI_auth_token_based {
	login(api_url, auth_data){
		this.token = auth_data
	}
}

class MinimAPI_auth_jwt extends MinimAPI_auth_token_based {
	handle_login_result(result){
		this.token = result.token
	}
}

class MinimAPI_auth_ecdsa extends MinimAPI_auth {

	static keys_parameters = {
		name: 'ECDSA',
		namedCurve: 'P-521',
	}
	static wrapping_algo = 'AES-GCM'

	static is_keys_saved(){
		return Boolean(localStorage.getItem('keys'))
	}

	#buf2hex(buffer){
		return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('')
	}

	#hex2buf(string) {
		return new Uint8Array(string.match(/.{1,2}/g).map(byte => parseInt(byte, 16)))
	}

	async #generate_keys(){
		return window.crypto.subtle.generateKey(this.constructor.keys_parameters, true, ['sign', 'verify'])
	}

	async #derive_shortpass(shortpass, salt, iterations){
		let shortpass_key = await window.crypto.subtle.importKey(
			'raw',
			new Uint8Array(new TextEncoder().encode(shortpass)),
			'PBKDF2',
			false,
			['deriveKey']
		)
		return await window.crypto.subtle.deriveKey(
			{
				'name': 'PBKDF2',
				salt: this.#hex2buf(salt),
				iterations: iterations,
				hash: {name: 'SHA-512'},
			},
			shortpass_key,
			{
				name: this.constructor.wrapping_algo,
				length: 256,
			},
			false,
			['wrapKey', 'unwrapKey']
		)
	}

	async #wrap_key(key, wrapping_key, iv){
		return await window.crypto.subtle.wrapKey(
			'jwk',
			key,
			wrapping_key,
			{
				name: this.constructor.wrapping_algo,
				iv: this.#hex2buf(iv)
			}
		)
	}

	async #unwrap_key(wrapped_key, unwrapping_key, iv, actions){
		return await window.crypto.subtle.unwrapKey(
			'jwk',
			this.#hex2buf(wrapped_key),
			unwrapping_key,
			{
				name: this.constructor.wrapping_algo,
				iv: this.#hex2buf(iv)
			},
			this.constructor.keys_parameters,
			true,
			actions
		)
	}

	async save_keys(shortpass){
		this.saved_data = {
			derivation_parameters: {
				salt: this.#buf2hex(window.crypto.getRandomValues(new Uint8Array(16))),
				iterations: Math.floor(Math.random() * (2000 - 1000 + 1) + 1000)
			},
			private_key: {
				iv: this.#buf2hex(window.crypto.getRandomValues(new Uint8Array(16))),
				wrapped_private_key: null
			},
			public_key: {
				iv: this.#buf2hex(window.crypto.getRandomValues(new Uint8Array(16))),
				wrapped_public_key: null
			},
			auth_id: this.auth_id
		}
		
		let derived_key = await this.#derive_shortpass(shortpass, this.saved_data.derivation_parameters.salt, this.saved_data.derivation_parameters.iterations)

		let wrapped_private_key = await this.#wrap_key(this.keys.privateKey, derived_key, this.saved_data.private_key.iv)
		this.saved_data.private_key.wrapped_private_key = this.#buf2hex(wrapped_private_key)

		let wrapped_public_key = await this.#wrap_key(this.keys.publicKey, derived_key, this.saved_data.public_key.iv)
		this.saved_data.public_key.wrapped_public_key = this.#buf2hex(wrapped_public_key)

		delete this.saved_data.derived_key
		localStorage.setItem('keys', JSON.stringify(this.saved_data))
	}

	async load_saved_keys(shortpass){
		this.keys = {}
		this.saved_data = JSON.parse(localStorage.getItem('keys'))
		
		let derived_key = await this.#derive_shortpass(shortpass, this.saved_data.derivation_parameters.salt, this.saved_data.derivation_parameters.iterations)
		
		this.keys.privateKey = await this.#unwrap_key(this.saved_data.private_key.wrapped_private_key, derived_key, this.saved_data.private_key.iv, ['sign'])

		this.keys.publicKey = await this.#unwrap_key(this.saved_data.public_key.wrapped_public_key, derived_key, this.saved_data.public_key.iv, ['verify'])

		this.auth_id = this.saved_data.auth_id
		delete this.saved_data
	}

	async login(api_url, auth_data){
		this.keys = await this.#generate_keys()
		let raw_public_key = await window.crypto.subtle.exportKey('raw', this.keys.publicKey)
		this.hex_public_key = this.#buf2hex(raw_public_key)
		auth_data.public_key = this.hex_public_key
		let login_result = await this.request(api_url+'auth', auth_data)
		this.handle_login_result(login_result)
	}

	handle_login_result(result){
		this.auth_id = result.id
	}

	async get_auth_header(method, path, data){
		let url = new URL(path, window.location.protocol + '//' + window.location.host)
		let timestamp = String(Math.floor(Date.now()/1000))
		let payload = timestamp+method+url.pathname+url.search+((data)?data:'')
		let signature = await window.crypto.subtle.sign(
			{
				name: 'ECDSA',
				hash: {name: 'SHA-512'},
			},
			this.keys.privateKey,
			new TextEncoder('utf-8').encode(payload)
		)
		return this.auth_id+'.'+this.#buf2hex(new Uint8Array(signature))+'.'+timestamp
	}
}