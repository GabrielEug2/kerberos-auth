
const moment = require('moment')

const REQUESTED_TIME_FORMAT = 'DD/MM/YYYY HH:mm'
const AUTORIZED_TIME_FORMAT = 'DD/MM/YYYY HH:mm'

/**
 * Verifica se o tempo solicitado está no formato certo.
 * @param {string} requestedTimeStr Tempo solicitado
 */
function requestedTimeIsValid(requestedTimeStr) {
    var requestedTime = moment(requestedTimeStr, REQUESTED_TIME_FORMAT, true)

    return requestedTime.isValid()
}

/**
 * Verifica se o tempo autorizado está em um formato válido.
 * @param {string} autorizedTimeStr Tempo autorizado
 */
function autorizedTimeIsValid(autorizedTimeStr) {
    /* O TGS implementado só trabalha com um formato de "tempo
    de acesso": "dd/mm/yyyy HH:MM", que significa que o
    cliente quer ou está autorizado a acessar o serviço até
    essa data.
        Se tivessem outros formatos (ex: um período específico,
    somente alguns dias da semana...), o serviço precisaria
    verificar se é algum destes formatos. */

    var autorizedTime = moment(autorizedTimeStr, AUTORIZED_TIME_FORMAT, true)

    return autorizedTime.isValid()
}

/**
 * Verifica se o tempo solicitado pelo cliente está
 * dentro do tempo autorizado pelo TGS.
 * @param {string} requestedTimeStr Tempo solicitado pelo cliente
 * @param {string} autorizedTimeStr Tempo autorizado pelo TGS
 */
function isAuthorized(requestedTimeStr, autorizedTimeStr) {
    var requestedTime = moment(requestedTimeStr, REQUESTED_TIME_FORMAT, true).toDate()
    var autorizedTime = moment(autorizedTimeStr, AUTORIZED_TIME_FORMAT, true).toDate()

    if (requestedTime < autorizedTime) {
        return true
    } else {
        return false
    }
}

module.exports = {
    requestedTimeIsValid: requestedTimeIsValid,
    autorizedTimeIsValid: autorizedTimeIsValid,
    isAuthorized: isAuthorized
}