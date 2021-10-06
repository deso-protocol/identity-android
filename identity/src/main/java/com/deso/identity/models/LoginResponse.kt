package com.deso.identity.models

import java.lang.Exception

sealed class LoginResponse

data class LoginSuccess(val selectedPublicKey: String, val allLoadedPublicKeys: List<String>) :
    LoginResponse()

data class LoginError(val error: Exception) : LoginResponse()
