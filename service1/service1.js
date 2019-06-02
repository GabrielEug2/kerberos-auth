
const express = require('express');

const config = require('./config');
const crypto = require('./crypto');
const timeValidator = require('./timeValidator');

const app = express();
const hostname = '127.0.0.1';
const port = 7000;

app.use(express.json());


app.post('/access', (req, res) => {
    message5 = req.body
    console.log(`Received: \n${JSON.stringify(message5, null, 4)}`)

    var expectedM5Fields = ['encryptedData', 'accessTicket']
    if (!expectedM5Fields.every( (p) => { return message5.hasOwnProperty(p) } )) {
        console.log("Mensagem não segue o formato especificado")
        return res.json({ error: "Mensagem não segue o formato especificado" })
    }

    try {
        var accessTicketStr = crypto.decrypt(message5.accessTicket, config.SERVICE_KEY)
        var accessTicket = JSON.parse(accessTicketStr)
    } catch(SyntaxError) {
        console.log('Falha ao descriptografar o ticket')
        return res.json({ error: 'Falha ao descriptografar o ticket' })
    }

    var expectedTicketFields = ['clientId', 'autorizedTime', 'sessionKey_ClientService']
    if (!expectedTicketFields.every((p) => { return accessTicket.hasOwnProperty(p) })) {
        console.log('Ticket não tem os campos esperados')
        return res.json({ error: 'Ticket não tem os campos esperados' })
    }

    if (!timeValidator.autorizedTimeIsValid(accessTicket.autorizedTime)) {
        console.log('Tempo autorizado não segue nenhum dos formatos válidos')
        return res.json({ error: 'Tempo autorizado não segue nenhum dos formatos válidos' })
    }

    try {
        var decryptedDataStr = crypto.decrypt(message5.encryptedData,
                                              accessTicket.sessionKey_ClientService)
        var decryptedData = JSON.parse(decryptedDataStr)
    } catch(SyntaxError) {
        console.log('Falha ao descriptografar a mensagem')
        return res.json({ error: 'Falha ao descriptografar a mensagem' })
    }

    var expectedClientFields = ['clientId', 'requestedTime', 'request', 'n3']
    if (!expectedClientFields.every( (p) => { return decryptedData.hasOwnProperty(p) } )) {
        console.log('Parte criptografada da mensagem não tem os campos esperados')
        return res.json({ error: 'Parte criptografada da mensagem não tem os campos esperados' })
    }
    if (!timeValidator.requestedTimeIsValid(decryptedData.requestedTime)) {
        console.log('Tempo solicitado não segue nenhum dos formatos válidos')
        return res.json({ error: 'Tempo solicitado não segue nenhum dos formatos válidos' })
    }

    clientMatches = decryptedData.clientId == accessTicket.clientId
    ticketIsValid = timeValidator.isAuthorized(
        decryptedData.requestedTime,
        accessTicket.autorizedTime
    )

    if (clientMatches && ticketIsValid) {
        response = "Você acessou o que queria!"

        var dataToEncrypt = {
            response: response,
            n3: decryptedData.n3,
        }
        var encryptedStrForClient = crypto.encrypt(JSON.stringify(dataToEncrypt),
                                                   accessTicket.sessionKey_ClientService)

        var message6 = {
            encryptedData: encryptedStrForClient
        }

        console.log(`Acesso concedido a '${accessTicket.clientId}'\n` +
                    `    Requisição "${decryptedData.request}"\n` +
                    `    Respondendo com "${response}"`)
        return res.json(message6)
    } else if (!clientMatches) {
        console.log(`Cliente ${decryptedData.clientId} tentou utilizar um ticket ` +
                    `que não lhe pertence (dono: ${accessTicket.clientId}`)
        return res.json({ error: 'Acesso negado. Ticket não é válido para esse cliente' })
    } else {
        console.log(`Acesso negado ao cliente ${decryptedData.clientId}\n` +
                    `  Tempo solicitado: ${decryptedData.requestedTime}\n` +
                    `  Tempo em que está autorizado: ${accessTicket.autorizedTime}`)
        return res.json({ error: 'Acesso negado. Ticket não é válido neste momento' })
    }
})

app.listen(port, hostname, () => console.log(`Server listening on port ${port}!`))