package net.hedtech.restfulapi

class UnauthorizedRequestException extends RuntimeException {
    String signature

    UnauthorizedRequestException(String signature) {
        this.signature = signature
    }

    @Override
    String getMessage() {
        "Signature ${this.signature} appears to be invalid. Request rejected!"
    }
}
