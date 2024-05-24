// get userDetails
let paramsString = window.location.search;
let searchParams = new URLSearchParams(paramsString);
console.log(`searchParams: ${searchParams}`);

const requestBody = {
  "client_id": searchParams.get("client_id"),
  "state": searchParams.get("state")
};

fetch('/login/plt', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(requestBody)
})
.then(response => response.json())
.then(data => {
    var info = {
        token: data.token,
        client_id: data.client_id,
        state: data.state
    };
    var jsonString = JSON.stringify(info);

    var qrcode = new QRCode(document.getElementById("qrcode"), {
        text: jsonString,
        width: 128,
        height: 128,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.M
    });

    // long pooling
    const requestBody2 = { token: data.token, ip: data.ip};

    const waitLogin = () => {
        fetch('/login/wait', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody2)
        })
        .then(response => {
            if (response.ok) {
                return response.json();
            } else {
                console.error('Login failed or timed out');
            }
        })
        .then(loginConsumeToken => {
            if (loginConsumeToken) {
                console.log('Login successfully', loginConsumeToken);
                const url = loginConsumeToken.result;
                // redirect
                window.location.href = url;
            }
        })
    };
    // start long pooling
    waitLogin();
});