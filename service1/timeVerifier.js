
const DATETIME_REGEX = /\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}/

/**
 * Verifica se o tempo solicitado está em um formato válido.
 * @param {string} clientTimeStr Tempo solicitado
 */
function requestedTimeIsValid(clientTimeStr) {
    /* O único formato de "tempo solicitado" que o cliente
    pode pedir para o serviço é uma data/horário no formato
    "dd/mm/yyyy HH:MM".
        Dependendo do serviço, poderia aceitar outras formas,
    como por exemplo um período de tempo. */
    if (clientTimeStr.match(DATETIME_REGEX)) {
        return true
    } else {
        return false
    }
}

/**
 * Verifica se o tempo autorizado está em um formato válido.
 * @param {string} autorizedTimeStr Tempo autorizado
 */
function autorizedTimeIsValid(autorizedTimeStr) {
    /* O Único formato de "tempo autorizado" implementado no TGS
    é um prazo de validade no formato "dd/mm/yyyy HH:MM", mas
    poderiam ter outros. */
    if (autorizedTimeStr.match(DATE_TIME_REGEX)) {
        return true
    } else {
        return false
    }
}

const EXPIRATION_DATE_CAPTURE_REGEX = /(\d{2})\/(\d{2})\/(\d{4}) (\d{2})\:(\d{2})/

/**
 * Verifica se o tempo solicitado pelo cliente está
 * dentro do tempo autorizado pelo TGS.
 * @param {string} clientTimeStr Tempo solicitado
 * @param {string} autorizedTimeStr Tempo autorizado
 */
function isAuthorized(clientTimeStr, autorizedTimeStr) {
    /* Como só tem um formato de "tempo solicitado" e
    um de "tempo autorizado", só tem uma forma de
    calcular.
        Se tivessem outros, cada combinação teria uma
    lógica diferente para verificar se está ou não
    autorizado. */
    var matches = clientTimeStr.match(EXPIRATION_DATE_CAPTURE_REGEX)
    var clientTime = new Date(
        matches[3], matches[2], matches[1],
        matches[4], matches[5]
    );

    matches = autorizedTimeStr.match(EXPIRATION_DATE_CAPTURE_REGEX)
    autorizedTime = new Date(
        matches[3], matches[2], matches[1],
        matches[4], matches[5]
    );

    if (clientTime < expirationDate) {
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