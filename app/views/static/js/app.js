import {render, html, svg} from 'https://unpkg.com/uhtml?module'

var authServer = ""

async function createCredential() {

    try {

        hideMessages()

        var username = document.querySelector('#username').value
        if (username === "") {
            errorMessage("Please enter a username")
            return;
        }
        var firstname = document.querySelector('#firstname').value
        if (firstname === "") {
            errorMessage("Please enter the first name")
            return;
        }
        var lastname = document.querySelector('#lastname').value
        if (lastname === "") {
            errorMessage("Please enter the last name")
            return;
        }

        // Create the object to send
        var data = {
            username: username,
            firstname: firstname,
            lastname: lastname,
        }

        // Perform a POST to the server
        var response = await fetch('/api/createcredential/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            mode: 'cors',
            body: JSON.stringify(data) // body data type must match "Content-Type" header
        });
        if (!response.ok) {
            var errorText = await response.text()
            console.log(errorText)
            throw new Error(errorText);
        }
        successMessage("successfully registered " + username)


    } catch (error) {
        errorMessage(error.message)
        return
    }

}


async function loginUser() {

    try {

        hideMessages()

        var username = document.querySelector('#email').value
        if (username === "") {
            errorMessage("Please enter a username")
            return;
        }

        // Get from the server the CredentialRequestOptions
        var response = await fetch(authServer + '/login/begin/' + username, {credentials:'include'})
        if (!response.ok) {
            var errorText = await response.text()
            console.log(errorText)
            throw new Error(errorText);
        }
        var responseJSON = await response.json()
        var credentialRequestOptions = responseJSON.options
        var session = responseJSON.session

        console.log("Received CredentialRequestOptions", credentialRequestOptions)

        // Decode the challenge from the server
        credentialRequestOptions.publicKey.challenge = bufferDecode(credentialRequestOptions.publicKey.challenge)

        // Decode each of the allowed credentials
        credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
            listItem.id = bufferDecode(listItem.id)
        });

        // Call the authenticator to create the assertion
        try {
            var assertion = await navigator.credentials.get({
                publicKey: credentialRequestOptions.publicKey
            })
        } catch (error) {
            // InvalidStateError
            errorMessage(error.message)
            console.log(error)
            return
        }
        console.log("Authenticator created Assertion", assertion)

        // Get the fields that we should encode for transmission to the server
        let authData = assertion.response.authenticatorData
        let clientDataJSON = assertion.response.clientDataJSON
        let rawId = assertion.rawId
        let sig = assertion.response.signature
        let userHandle = assertion.response.userHandle

        // Create the object to send
        var data = {
            id: assertion.id,
            rawId: bufferEncode(rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferEncode(authData),
                clientDataJSON: bufferEncode(clientDataJSON),
                signature: bufferEncode(sig),
                userHandle: bufferEncode(userHandle),
            },
        }

        var wholeData = {
            response: data,
            session: session
        }

        // Perform a POST to the server
        var response = await fetch(authServer + '/login/finish/' + username, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'session_id': session
            },
            credentials: 'include',
            mode: 'cors',
            body: JSON.stringify(wholeData) // body data type must match "Content-Type" header
        });
        if (!response.ok) {
            var errorText = await response.text()
            console.log(errorText)
            throw new Error(errorText);
        }
        successMessage("successfully logged in " + username)


    } catch (error) {
        errorMessage(error.message)
        return
    }

}

// Base64 to ArrayBuffer
function bufferDecode(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

// ArrayBuffer to URLBase64
function bufferEncode(value) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");;
}

async function getCredentialList(backEndpoint) {
    backEndpoint = "http://127.0.0.1:8080/api/allcredentials"

    try {
        let response = await fetch(backEndpoint)
        var cards = await response.json()
    } catch (error) {
        log.error(error)
        return null
    }

    return cards

}

function normalMessage(text) {
    document.querySelector('#normalmessage').innerHTML = text
}
function errorMessage(text) {
    document.querySelector('#errormessage').innerHTML = text
}
function successMessage(text) {
    document.querySelector('#successmessage').innerHTML = text
}
function hideMessages() {
    document.querySelector('#normalmessage').innerHTML = ""
    document.querySelector('#errormessage').innerHTML = ""
    document.querySelector('#successmessage').innerHTML = ""
}

function prueba() {
    var mainElem = document.querySelector('main')
    if (mainElem) {
        var theHtml = html`<p>Hola</p>`
        render(mainElem, theHtml)
    }    
}


window.createCredential = createCredential
