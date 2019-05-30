
const express = require('express');

const config = require('./config');
const crypto = require('./crypto');
const timeVerifier = require('./timeVerifier');

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
        res.json({ error: "Mensagem não segue o formato especificado" })
        return
    }

    try {
        var accessTicketStr = crypto.decrypt(message5.ticket, config.SERVICE_KEY)
        var accessTicket = JSON.parse(accessTicketStr)

        var expectedTicketFields = ['clientId', 'autorizedTime', 'sessionKey_ClientService']
        if (!expectedTicketFields.every( (p) => { return accessTicket.hasOwnProperty(p) } ) ||
            !timeVerifier.autorizedTimeIsValid(accessTicket.autorizedTime)) {
            console.log('Ticket não segue o formato especificado.')
            res.json({ error: 'Ticket não segue o formato especificado.' })
            return
        }
    } catch(SyntaxError) {
        console.log('Ticket não segue o formato especificado.')
        res.json({ error: 'Ticket não segue o formato especificado.' })
        return
    }
    try {

    }
    try {
        var clientDataStr = crypto.decrypt(message5.encryptedData,
                                           accessTicket.sessionKey_ClientService)
        var clientData = JSON.parse(clientDataStr)
    } catch(SyntaxError) {
        console.log('Parte criptografada da mensagem não tem campos esperados')
        res.json({ error: 'Parte criptografada da mensagem não tem campos esperados' })
        return
    }
    var expectedClientFields = ['clientId', 'currentTime', 'request', 'n3']
    if (!expectedClientFields.every( (p) => { return clientData.hasOwnProperty(p) } )) {
        console.log('Parte criptografada da mensagem não tem campos esperados')
        res.json({ error: 'Parte criptografada da mensagem não tem campos esperados' })
        return
    }

    clientMatches = clientData.clientId == accessTicket.clientId
    requested_time_is_valid = timeVerifier.isValid(clientData.currentTime)
    timeIsWithinAutorizedTime = timeVerifier.isAutorized(
        clientData.currentTime,
        accessTicket.autorizedTime
    )
    try {
        timeIsWithinAutorizedTime = timeVerifier.isValid(clientData.currentTime,
            accessTicket.autorizedTime)
    } catch (exception) {
        console.log(exception)
        res.json({ error: 'Tempo solicitado ou tempo autorizado inválidos' })
        return
    }

    if (clientMatches && timeIsWithinAutorizedTime) {
        response = "Something"

        var dataToEncrypt = {
            response: response,
            n3: clientData.n3,
        }
        var encryptedStrForClient = crypto.encrypt(JSON.stringify(dataToEncrypt),
                                                   accessTicket.sessionKey_ClientService)

        var message6 = {
            encryptedData: encryptedStrForClient
        }

        console.log(`Acesso concedido a '${accessTicket.clientId}'\n` +
                    `    Respondendo com "${response}"`)

        res.json(message6)
    } else if (!clientMatches) {
        console.log(`Cliente ${clientData.clientId} tentou utilizar um ticket ` +
                    `que não lhe pertence (dono: ${accessTicket.clientId}`)
        res.json({ error: 'Acesso negado. Ticket não é válido para esse cliente' })
    } else {
        console.log(`Acesso negado ao cliente ${clientData.clientId}\n` +
                    `  Tempo solicitado: ${clientData.currentTime}\n` +
                    `  Tempo em que está autorizado: ${accessTicket.autorizedTime}`)
        res.json({ error: 'Acesso negado. Ticket não é válido neste momento' })
    }
})

app.listen(port, hostname, () => console.log(`Server listening on port ${port}!`))